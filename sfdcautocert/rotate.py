"""Rotation of a Salesforce-held certificate through the CSR flow, with a pluggable signer."""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from typing import Optional, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import certstore
from .issue import enforce_purpose
from .sf.metadata import MetadataClient


class Signer(Protocol):
    def sign(self, csr_pem: bytes) -> bytes:
        """Return the signed leaf followed by intermediates (PEM)."""


class CommandSigner:
    """Delegates to an external command: CSR PEM on stdin, signed chain PEM on stdout.
    Fits Vault PKI / AWS Private CA / step-ca / ADCS wrappers without extra dependencies."""

    def __init__(self, command: list[str], timeout: float = 120.0):
        self.command, self.timeout = command, timeout

    def sign(self, csr_pem: bytes) -> bytes:
        p = subprocess.run(self.command, input=csr_pem, capture_output=True, timeout=self.timeout)
        if p.returncode != 0:
            raise RuntimeError(f"signer failed ({p.returncode}): {p.stderr.decode(errors='replace')[:300]}")
        return p.stdout


def rotate(client: MetadataClient, base_name: str, signer: Signer, purpose: str = "client",
           now: Optional[datetime] = None) -> str:
    """Create `<base_name>_<YYYYMMDD>` next to the current certificate, have it signed and install it.
    The old certificate is untouched (overlap); repointing consumers and retiring it is a separate step.
    Returns the new DeveloperName. Refuses certificates whose EKU does not match `purpose`."""
    now = now or datetime.now(timezone.utc)
    new_name = f"{base_name}_{now:%Y%m%d}"
    csr = certstore.request_csr(client, new_name, label=new_name)
    chain = signer.sign(csr.public_bytes(serialization.Encoding.PEM))
    leaf = x509.load_pem_x509_certificates(chain)[0]
    enforce_purpose(leaf, purpose)
    certstore.install_signed(client, new_name, chain, label=new_name)
    return new_name
