"""Key/CSR generation, purpose enforcement, renewal window and retry backoff."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .analyze import build_record
from .model import CertRecord
from .acme import AcmeClient

PURPOSES = {"server": {"serverAuth"}, "client": {"clientAuth"}}


class PurposeViolation(RuntimeError):
    pass


def new_key(kind: str = "ec-p256"):
    if kind == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind in ("rsa-3072", "rsa-4096"):
        return rsa.generate_private_key(65537, int(kind.split("-")[1]))
    raise ValueError(f"unknown key type {kind}")


def make_csr(key, domains: list[str]) -> bytes:
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.DER)


def enforce_purpose(cert: x509.Certificate, purpose: str) -> CertRecord:
    """Refuse certificates whose EKU is not exactly the requested purpose (no dual-use)."""
    rec = build_record(cert, "acme", cert.subject.rfc4514_string())
    if set(rec.eku) != PURPOSES[purpose]:
        raise PurposeViolation(
            f"issued certificate EKU {sorted(rec.eku) or 'none'} does not match required purpose '{purpose}' "
            f"({sorted(PURPOSES[purpose])}); refusing to deploy")
    return rec


@dataclass
class IssuedCert:
    key_pem: bytes
    chain_pem: str
    leaf: x509.Certificate
    record: CertRecord


def issue(client: AcmeClient, domains: list[str], solver, purpose: str, key_type: str = "ec-p256") -> IssuedCert:
    key = new_key(key_type)
    pem = client.obtain(domains, make_csr(key, domains), solver)
    certs = x509.load_pem_x509_certificates(pem.encode())
    rec = enforce_purpose(certs[0], purpose)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return IssuedCert(key_pem, pem, certs[0], rec)


def renewal_due(not_before: datetime, not_after: datetime, now: Optional[datetime] = None) -> bool:
    """Renew once ~1/3 of the lifetime remains (47d cert -> from day ~31, i.e. ~16d before expiry).
    Longer certs renew 30 days before expiry at the latest."""
    now = now or datetime.now(timezone.utc)
    life = not_after - not_before
    remaining = not_after - now
    from datetime import timedelta
    return remaining <= min(life / 3, timedelta(days=30))


def backoff_seconds(attempt: int, base: float = 60.0, cap: float = 6 * 3600.0) -> float:
    """Exponential backoff for CA failures: 1m, 2m, 4m ... capped at 6h."""
    return min(cap, base * (2 ** attempt))
