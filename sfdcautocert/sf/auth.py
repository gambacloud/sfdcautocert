"""Server-side Salesforce authentication. All calls are made by the backend, so no
browser/CORS configuration is needed on the Connected App."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


@dataclass
class Session:
    access_token: str
    instance_url: str

    def __repr__(self) -> str:  # never leak the token in logs
        return f"Session({self.instance_url})"


def from_sf_cli(org: str) -> Session:
    """Dev convenience: reuse the token of an org already authorised with the sf CLI."""
    sf = shutil.which("sf")
    if not sf:
        raise RuntimeError("sf CLI not found on PATH")
    # `org display` returns a redacted token; `show-access-token` returns the real one (and refreshes it if expired).
    # The token stays in process memory only and is never printed.
    proc = subprocess.run([sf, "org", "auth", "show-access-token", "-o", org, "--json"], capture_output=True, text=True)
    data = json.loads(proc.stdout or "{}")
    if data.get("status") != 0:
        raise RuntimeError(f"sf show-access-token failed: {data.get('message') or proc.stderr}")
    token = data["result"]["accessToken"]
    info = json.loads(subprocess.run([sf, "org", "display", "-o", org, "--json"], capture_output=True, text=True).stdout)
    return Session(token, info["result"]["instanceUrl"])


def _b64(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def from_jwt_bearer(client_id: str, username: str, key_file: Path, login_url: str = "https://login.salesforce.com") -> Session:
    """OAuth 2.0 JWT bearer flow (headless, server-to-server). Needs a Connected App with
    'Use digital signatures' set to the certificate matching key_file."""
    header = _b64(json.dumps({"alg": "RS256"}).encode())
    claims = _b64(json.dumps({"iss": client_id, "sub": username, "aud": login_url, "exp": int(time.time()) + 180}).encode())
    signing_input = header + b"." + claims
    key = serialization.load_pem_private_key(Path(key_file).read_bytes(), password=None)
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    body = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": (signing_input + b"." + _b64(sig)).decode(),
    }).encode()
    req = urllib.request.Request(f"{login_url}/services/oauth2/token", data=body)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read())
            raise RuntimeError(f"JWT bearer login failed: {err.get('error')}: {err.get('error_description')}") from None
        except ValueError:
            raise RuntimeError(f"JWT bearer login failed: HTTP {e.code}") from None
    return Session(data["access_token"], data["instance_url"])
