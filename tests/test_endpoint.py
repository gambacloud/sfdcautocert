"""TLS endpoint classification against local servers (loopback scanning is allowed only for these tests)."""
import datetime as dt
import os
import socket
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sfdcautocert import relevance, sources

NOW = dt.datetime.now(dt.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name("Test CA")).issuer_name(name("Test CA")).public_key(key.public_key())
            .serial_number(1).not_valid_before(NOW - dt.timedelta(days=30)).not_valid_after(NOW + dt.timedelta(days=300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)  # Python 3.13+ verifies strictly
            .sign(key, hashes.SHA256()))
    return key, cert


def leaf(ca_key, ca_cert, san, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    nb, na = (NOW - dt.timedelta(days=60), NOW - dt.timedelta(days=1)) if expired else (NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=40))
    cert = (x509.CertificateBuilder().subject_name(name(san)).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


class Server:
    def __init__(self, key, cert, tmp):
        self.cert_file, self.key_file = os.path.join(tmp, f"{id(key)}.crt"), os.path.join(tmp, f"{id(key)}.key")
        open(self.cert_file, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        open(self.key_file, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.cert_file, self.key_file)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                s, _ = self.sock.accept()
                self.ctx.wrap_socket(s, server_side=True).close()
            except Exception:
                if self.sock.fileno() == -1:
                    return


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["SFDCAUTOCERT_ALLOW_PRIVATE"] = "1"
        cls.tmp = tempfile.mkdtemp()
        cls.ca_key, cls.ca = make_ca()
        cls.ca_file = os.path.join(cls.tmp, "ca.pem")
        open(cls.ca_file, "wb").write(cls.ca.public_bytes(serialization.Encoding.PEM))

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("SFDCAUTOCERT_ALLOW_PRIVATE", None)

    def scan(self, san, expired=False, cafile=None):
        srv = Server(*leaf(self.ca_key, self.ca, san, expired), self.tmp)
        rec = sources.scan_endpoint("localhost", srv.port, timeout=5, cafile=None if cafile == "default" else (cafile or self.ca_file))
        srv.sock.close()
        return rec, {f.code for f in rec.findings}

    def test_valid(self):
        rec, codes = self.scan("localhost")
        self.assertTrue(rec.extra["mozilla_trusted"])
        self.assertFalse(codes & {"HOSTNAME_MISMATCH", "UNTRUSTED_CHAIN", "EXPIRED"})
        self.assertEqual(relevance.classify(rec)[0], "NOT_AFFECTED")

    def test_hostname_mismatch_is_not_reported_as_untrusted_chain(self):
        rec, codes = self.scan("other.example")
        self.assertIn("HOSTNAME_MISMATCH", codes)
        self.assertNotIn("UNTRUSTED_CHAIN", codes)
        self.assertTrue(rec.extra["mozilla_trusted"])  # the chain itself validated
        level, why = relevance.classify(rec)
        self.assertEqual(level, "ACTION")
        self.assertIn("hostname", why)

    def test_expired(self):
        rec, codes = self.scan("localhost", expired=True)
        self.assertIn("EXPIRED", codes)
        self.assertNotIn("UNTRUSTED_CHAIN", codes)
        self.assertEqual(relevance.classify(rec)[0], "ACTION")

    def test_unknown_ca_is_untrusted_chain(self):
        rec, codes = self.scan("localhost", cafile="default")  # default store: our CA is unknown
        self.assertIn("UNTRUSTED_CHAIN", codes)
        self.assertFalse(rec.extra["mozilla_trusted"])
        self.assertIn("custom CA", relevance.classify(rec)[1])

    def test_chain_extraction_falls_back_to_private_sslobject(self):
        class Cert:
            def public_bytes(self, fmt):
                return b"der" + bytes([fmt])

        class Obj:
            def get_verified_chain(self):
                return [Cert()]

        class Sock:  # no public get_verified_chain (Python < 3.13)
            _sslobj = Obj()

        self.assertEqual(sources._chain_der(Sock(), True), [b"der" + bytes([sources._ENCODING_DER])])
        self.assertEqual(sources._chain_der(object(), True), [])


if __name__ == "__main__":
    unittest.main()
