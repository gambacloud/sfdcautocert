"""Minimal RFC 8555 (ACME) client: account, order, http-01 / dns-01 challenges, finalize, download.

CA agnostic (Let's Encrypt, DigiCert, Sectigo, step-ca, Vault PKI ...). Account key is ES256.
"""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


class AcmeError(RuntimeError):
    def __init__(self, msg: str, problem: Optional[dict] = None):
        super().__init__(msg)
        self.problem = problem or {}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_of(key: ec.EllipticCurvePrivateKey) -> dict:
    n = key.public_key().public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def thumbprint(jwk: dict) -> str:
    return b64u(hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()).digest())


# ---------------------------------------------------------------- challenge solvers

class HttpSolver:
    """Serves /.well-known/acme-challenge/<token> for http-01 (needs the port reachable by the CA)."""
    challenge_type = "http-01"

    def __init__(self, port: int = 80, host: str = "0.0.0.0"):
        self.tokens: dict[str, str] = {}
        tokens = self.tokens

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = tokens.get(self.path.rsplit("/", 1)[-1])
                self.send_response(200 if body else 404)
                self.end_headers()
                if body:
                    self.wfile.write(body.encode())

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer((host, port), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def present(self, domain: str, token: str, key_authz: str) -> None:
        self.tokens[token] = key_authz

    def cleanup(self, domain: str, token: str, key_authz: str) -> None:
        self.tokens.pop(token, None)

    def close(self) -> None:
        self.server.shutdown()


class DnsHookSolver:
    """dns-01 via an external command: `<cmd> present|cleanup <fqdn> <txt-value>` (Route53, Cloudflare, ...)."""
    challenge_type = "dns-01"

    def __init__(self, command: list[str], propagation_wait: float = 20.0):
        self.command, self.wait = command, propagation_wait

    def present(self, domain: str, token: str, key_authz: str) -> None:
        value = b64u(hashlib.sha256(key_authz.encode()).digest())
        subprocess.run([*self.command, "present", f"_acme-challenge.{domain}", value], check=True)
        time.sleep(self.wait)

    def cleanup(self, domain: str, token: str, key_authz: str) -> None:
        value = b64u(hashlib.sha256(key_authz.encode()).digest())
        subprocess.run([*self.command, "cleanup", f"_acme-challenge.{domain}", value], check=False)


# ---------------------------------------------------------------- client

class AcmeClient:
    def __init__(self, directory_url: str, account_key: Optional[ec.EllipticCurvePrivateKey] = None,
                 ssl_context: Optional[ssl.SSLContext] = None, timeout: float = 30.0):
        self.directory_url = directory_url
        self.key = account_key or ec.generate_private_key(ec.SECP256R1())
        self.ctx, self.timeout = ssl_context, timeout
        self.kid: Optional[str] = None
        self._nonce: Optional[str] = None
        self.directory = self._get_json(directory_url)

    # -- transport
    def _open(self, req: urllib.request.Request):
        try:
            return urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                prob = json.loads(raw)
            except ValueError:
                prob = {"detail": raw[:200].decode("utf-8", "replace")}
            self._nonce = e.headers.get("Replay-Nonce") or self._nonce
            raise AcmeError(f"{prob.get('type', 'http ' + str(e.code))}: {prob.get('detail', '')}", prob) from None

    def _get_json(self, url: str) -> dict:
        with self._open(urllib.request.Request(url)) as r:
            return json.loads(r.read())

    def _new_nonce(self) -> str:
        req = urllib.request.Request(self.directory["newNonce"], method="HEAD")
        with self._open(req) as r:
            return r.headers["Replay-Nonce"]

    def _post(self, url: str, payload, retry: bool = True):
        """JWS POST. payload=None -> POST-as-GET. Returns (parsed-or-raw body, headers)."""
        protected = {"alg": "ES256", "nonce": self._nonce or self._new_nonce(), "url": url}
        if self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = jwk_of(self.key)
        p64 = b64u(json.dumps(protected).encode())
        pl64 = "" if payload is None else b64u(json.dumps(payload).encode())
        r_, s_ = decode_dss_signature(self.key.sign(f"{p64}.{pl64}".encode(), ec.ECDSA(hashes.SHA256())))
        body = json.dumps({"protected": p64, "payload": pl64,
                           "signature": b64u(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/jose+json"})
        self._nonce = None
        try:
            with self._open(req) as r:
                self._nonce = r.headers.get("Replay-Nonce")
                raw = r.read()
                ctype = r.headers.get("Content-Type", "")
                return (json.loads(raw) if "json" in ctype else raw.decode()), r.headers
        except AcmeError as e:
            if retry and e.problem.get("type", "").endswith(":badNonce"):
                return self._post(url, payload, retry=False)
            raise

    # -- protocol
    def register(self, contact: Optional[list[str]] = None) -> str:
        payload = {"termsOfServiceAgreed": True}
        if contact:
            payload["contact"] = contact
        _, h = self._post(self.directory["newAccount"], payload)
        self.kid = h["Location"]
        return self.kid

    def obtain(self, domains: list[str], csr_der: bytes, solver, poll: float = 1.0, timeout: float = 300.0) -> str:
        """Run a full order for `domains`; returns the issued certificate chain (PEM)."""
        if not self.kid:
            self.register()
        order, h = self._post(self.directory["newOrder"],
                              {"identifiers": [{"type": "dns", "value": d} for d in domains]})
        order_url = h["Location"]
        deadline = time.time() + timeout
        for authz_url in order["authorizations"]:
            self._solve(authz_url, solver, poll, deadline)
        self._post(order["finalize"], {"csr": b64u(csr_der)})
        while True:
            order, _ = self._post(order_url, None)
            if order["status"] == "valid":
                break
            if order["status"] == "invalid" or time.time() > deadline:
                raise AcmeError(f"order {order['status']}: {order.get('error', '')}", order.get("error"))
            time.sleep(poll)
        pem, _ = self._post(order["certificate"], None)
        return pem

    def _solve(self, authz_url: str, solver, poll: float, deadline: float) -> None:
        authz, _ = self._post(authz_url, None)
        if authz["status"] == "valid":
            return
        domain = authz["identifier"]["value"]
        ch = next((c for c in authz["challenges"] if c["type"] == solver.challenge_type), None)
        if not ch:
            raise AcmeError(f"CA offers no {solver.challenge_type} challenge for {domain}")
        key_authz = f"{ch['token']}.{thumbprint(jwk_of(self.key))}"
        solver.present(domain, ch["token"], key_authz)
        try:
            self._post(ch["url"], {})
            while True:
                authz, _ = self._post(authz_url, None)
                if authz["status"] == "valid":
                    return
                if authz["status"] != "pending" and authz["status"] != "processing":
                    err = next((c.get("error") for c in authz["challenges"] if c.get("error")), None)
                    raise AcmeError(f"authorization for {domain} {authz['status']}: {err}", err)
                if time.time() > deadline:
                    raise AcmeError(f"authorization for {domain} timed out")
                time.sleep(poll)
        finally:
            solver.cleanup(domain, ch["token"], key_authz)
