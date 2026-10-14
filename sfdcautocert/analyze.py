from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from .model import CertRecord, Finding

EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
}

# Thresholds from the countdown spec: green > 20, yellow 10-20, red < 10
RED_DAYS = 10
YELLOW_DAYS = 20
TARGET_LIFETIME_DAYS = 47


def parse_certs(data: bytes) -> list[x509.Certificate]:
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificates(data)
    return [x509.load_der_x509_certificate(data)]


def _key_info(cert: x509.Certificate) -> tuple[str, Optional[int]]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC-{key.curve.name}", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return type(key).__name__, None


def build_record(
    cert: x509.Certificate,
    source: str,
    name: str,
    location: str = "",
    extra: Optional[dict] = None,
    now: Optional[datetime] = None,
) -> CertRecord:
    now = now or datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc

    eku: list[str] = []
    has_eku = True
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku = [EKU_NAMES.get(o.dotted_string, o.dotted_string) for o in ext.value]
    except x509.ExtensionNotFound:
        has_eku = False

    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [str(v.value) for v in ext.value]
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        pass

    key_type, key_size = _key_info(cert)
    try:
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name
    except Exception:
        sig_alg = None

    rec = CertRecord(
        source=source,
        name=name,
        location=location,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        not_before=not_before,
        not_after=not_after,
        days_left=(not_after - now).days,
        validity_days=(not_after - not_before).days,
        key_type=key_type,
        key_size=key_size,
        sig_alg=sig_alg,
        eku=eku,
        san=san,
        self_signed=cert.subject == cert.issuer,
        is_ca=is_ca,
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        extra=dict(extra or {}),
    )
    rec.extra["has_eku"] = has_eku
    rec.findings = evaluate(rec)
    return rec


def evaluate(rec: CertRecord) -> list[Finding]:
    """Rule engine. Self-signed / custom-CA certs are unaffected by the public-CA
    dual-use ban (per the Salesforce notice), so those findings are downgraded."""
    out: list[Finding] = []
    public_pki = not rec.self_signed and not rec.extra.get("custom_ca", False)

    if rec.days_left is not None:
        d = rec.days_left
        if d < 0:
            out.append(Finding("EXPIRED", "CRITICAL", f"expired {-d} days ago"))
        elif d < RED_DAYS:
            out.append(Finding("EXPIRES_SOON", "HIGH", f"expires in {d} days (< {RED_DAYS})"))
        elif d <= YELLOW_DAYS:
            out.append(Finding("EXPIRES_SOON", "MEDIUM", f"expires in {d} days (< {YELLOW_DAYS + 1})"))

    if "serverAuth" in rec.eku and "clientAuth" in rec.eku:
        if public_pki:
            out.append(Finding("DUAL_USE", "CRITICAL",
                               "EKU has serverAuth + clientAuth: dual-use certs are being banned; split into separate server/client certs"))
        else:
            out.append(Finding("DUAL_USE", "INFO", "dual-use EKU, but self-signed/private CA (not covered by the public-CA ban)"))
    elif not rec.extra.get("has_eku", True) and not rec.is_ca:
        out.append(Finding("NO_EKU", "INFO", "no EKU extension: usage is unrestricted (acts as both server and client)"))

    if public_pki and not rec.is_ca and rec.validity_days and rec.validity_days > TARGET_LIFETIME_DAYS:
        out.append(Finding("LONG_LIFETIME", "LOW",
                           f"validity {rec.validity_days}d; public TLS lifetimes are heading to {TARGET_LIFETIME_DAYS}d - rotation must be automated"))

    if rec.key_type == "RSA" and rec.key_size and rec.key_size < 2048:
        out.append(Finding("WEAK_KEY", "HIGH", f"RSA {rec.key_size}-bit key"))
    elif rec.key_type == "DSA":
        out.append(Finding("WEAK_KEY", "HIGH", "DSA key"))
    if rec.sig_alg in ("sha1", "md5", "md2"):
        out.append(Finding("WEAK_SIG", "HIGH", f"{rec.sig_alg} signature"))
    return out
