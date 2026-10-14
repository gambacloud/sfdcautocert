import base64
import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID as E, NameOID

from sfdcautocert import acme, issue


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FakeCA:
    """In-process RFC 8555 server: verifies JWS signatures, nonces and key authorizations."""

    def __init__(self, ekus):
        self.ekus, self.nonces, self.accounts, self.authz, self.orders = ekus, set(), {}, {}, {}
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.n = 0
        self.bad_nonce_once = True
        ca = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj=None, headers=None, raw=None, ctype="application/json"):
                body = raw if raw is not None else json.dumps(obj or {}).encode()
                self.send_response(code)
                nonce = f"n{ca.n}"
                ca.n += 1
                ca.nonces.add(nonce)
                self.send_header("Replay-Nonce", nonce)
                self.send_header("Content-Type", ctype)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_HEAD(self):
                self._send(200)

            def do_GET(self):
                base = ca.base
                self._send(200, {"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                prot = json.loads(b64d(body["protected"]))
                if ca.bad_nonce_once and self.path != "/acct":
                    ca.bad_nonce_once = False
                    return self._send(400, {"type": "urn:ietf:params:acme:error:badNonce", "detail": "retry"})
                assert prot["nonce"] in ca.nonces, "nonce reuse/unknown"
                ca.nonces.discard(prot["nonce"])
                assert prot["url"] == ca.base + self.path
                jwk = prot.get("jwk") or ca.accounts[prot["kid"]]
                pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64d(jwk["x"]), "big"),
                                                    int.from_bytes(b64d(jwk["y"]), "big"), ec.SECP256R1()).public_key()
                sig = b64d(body["signature"])
                pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                           f"{body['protected']}.{body['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
                payload = json.loads(b64d(body["payload"])) if body["payload"] else None
                p = self.path
                if p == "/acct":
                    kid = ca.base + "/acct/1"
                    ca.accounts[kid] = jwk
                    return self._send(201, {"status": "valid"}, {"Location": kid})
                if p == "/order":
                    ids = [i["value"] for i in payload["identifiers"]]
                    ca.orders["1"] = {"domains": ids, "status": "pending"}
                    for i, d in enumerate(ids):
                        ca.authz[str(i)] = {"domain": d, "status": "pending", "token": f"tok{i}", "jwk": jwk}
                    return self._send(201, {"status": "pending", "identifiers": payload["identifiers"],
                                            "authorizations": [f"{ca.base}/authz/{i}" for i in range(len(ids))],
                                            "finalize": ca.base + "/finalize/1"}, {"Location": ca.base + "/order/1"})
                if p.startswith("/authz/"):
                    a = ca.authz[p.rsplit("/", 1)[1]]
                    return self._send(200, {"status": a["status"], "identifier": {"type": "dns", "value": a["domain"]},
                                            "challenges": [{"type": "http-01", "url": f"{ca.base}/chall/{p.rsplit('/', 1)[1]}",
                                                            "token": a["token"], "status": a["status"]}]})
                if p.startswith("/chall/"):
                    i = p.rsplit("/", 1)[1]
                    a = ca.authz[i]
                    expected = f"{a['token']}.{acme.thumbprint(a['jwk'])}"
                    ca.authz[i]["status"] = "valid" if ca.presented.get(a["domain"]) == expected else "invalid"
                    return self._send(200, {"status": "processing"})
                if p == "/finalize/1":
                    csr = x509.load_der_x509_csr(b64d(payload["csr"]))
                    assert csr.is_signature_valid
                    ca.orders["1"]["csr"] = csr
                    ca.orders["1"]["status"] = "valid"
                    return self._send(200, {"status": "processing"})
                if p == "/order/1":
                    o = ca.orders["1"]
                    out = {"status": o["status"]}
                    if o["status"] == "valid":
                        out["certificate"] = ca.base + "/cert/1"
                    return self._send(200, out)
                if p == "/cert/1":
                    csr = ca.orders["1"]["csr"]
                    now = datetime.now(timezone.utc)
                    cert = (x509.CertificateBuilder().subject_name(csr.subject)
                            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Test CA")]))
                            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                            .not_valid_before(now).not_valid_after(now + timedelta(days=47))
                            .add_extension(x509.ExtendedKeyUsage(ca.ekus), False).sign(ca.ca_key, hashes.SHA256()))
                    return self._send(200, raw=cert.public_bytes(serialization.Encoding.PEM),
                                      ctype="application/pem-certificate-chain")
                self._send(404, {"type": "notfound"})

        self.presented = {}
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


class RecordingSolver:
    challenge_type = "http-01"

    def __init__(self, ca):
        self.ca = ca

    def present(self, domain, token, key_authz):
        self.ca.presented[domain] = key_authz

    def cleanup(self, *a):
        pass


class AcmeTests(unittest.TestCase):
    def run_issue(self, ekus, purpose):
        ca = FakeCA(ekus)
        try:
            client = acme.AcmeClient(ca.base + "/dir")
            return issue.issue(client, ["svc.example.com", "svc2.example.com"], RecordingSolver(ca), purpose)
        finally:
            ca.close()

    def test_full_flow_client_cert(self):
        res = self.run_issue([E.CLIENT_AUTH], "client")
        self.assertEqual(res.record.eku, ["clientAuth"])
        self.assertEqual(res.leaf.subject.rfc4514_string(), "CN=svc.example.com")
        self.assertIn(b"PRIVATE KEY", res.key_pem)

    def test_dual_use_issuance_refused(self):
        with self.assertRaises(issue.PurposeViolation):
            self.run_issue([E.SERVER_AUTH, E.CLIENT_AUTH], "client")

    def test_renewal_window_47d(self):
        nb = datetime(2026, 1, 1, tzinfo=timezone.utc)
        na = nb + timedelta(days=47)
        self.assertFalse(issue.renewal_due(nb, na, nb + timedelta(days=20)))
        self.assertTrue(issue.renewal_due(nb, na, nb + timedelta(days=32)))  # 15d left

    def test_backoff(self):
        self.assertEqual([issue.backoff_seconds(i) for i in range(3)], [60, 120, 240])
        self.assertEqual(issue.backoff_seconds(20), 6 * 3600)


if __name__ == "__main__":
    unittest.main()
