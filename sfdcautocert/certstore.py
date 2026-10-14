"""Salesforce-side certificate lifecycle via the CSR flow (Metadata API, server-side).

The private key is generated inside Salesforce and never leaves it:
  1. request_csr()    - create a CA-signed-type certificate; Salesforce returns a CSR
  2. (sign the CSR with your CA - ACME / Vault / AWS Private CA / Microsoft CA)
  3. install_signed() - upload the signed chain; the certificate becomes usable
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .sf.metadata import MetadataClient, MetadataError

_NS = "http://soap.sforce.com/2006/04/metadata"


def _files(dev_name: str, label: str, key_size: int, crt: bytes) -> dict[str, bytes]:
    package = (f'<?xml version="1.0" encoding="UTF-8"?>\n<Package xmlns="{_NS}"><types><members>{dev_name}</members>'
               "<name>Certificate</name></types><version>62.0</version></Package>")
    meta = (f'<?xml version="1.0" encoding="UTF-8"?>\n<Certificate xmlns="{_NS}">\n'
            "    <caSigned>true</caSigned>\n    <encryptedWithPlatformEncryption>false</encryptedWithPlatformEncryption>\n"
            f"    <keySize>{key_size}</keySize>\n    <masterLabel>{label}</masterLabel>\n"
            "    <privateKeyExportable>false</privateKeyExportable>\n</Certificate>\n")
    return {"package.xml": package.encode(), f"certs/{dev_name}.crt": crt, f"certs/{dev_name}.crt-meta.xml": meta.encode()}


def fetch_csr(client: MetadataClient, dev_name: str) -> x509.CertificateSigningRequest:
    blob = client.retrieve("Certificate").get(f"certs/{dev_name}.crt")
    if blob is None:
        raise MetadataError(f"certificate {dev_name} not found")
    if b"BEGIN CERTIFICATE REQUEST" not in blob:
        raise MetadataError(f"certificate {dev_name} is not pending (no CSR available)")
    return x509.load_pem_x509_csr(blob)


def request_csr(client: MetadataClient, dev_name: str, label: str | None = None,
                key_size: int = 2048) -> x509.CertificateSigningRequest:
    client.deploy(_files(dev_name, label or dev_name, key_size, b""))
    return fetch_csr(client, dev_name)


def install_signed(client: MetadataClient, dev_name: str, chain_pem: bytes | str,
                   label: str | None = None, key_size: int = 2048) -> None:
    """Upload leaf (first) + intermediates. Refuses a leaf whose public key differs from the pending CSR."""
    pem = chain_pem.encode() if isinstance(chain_pem, str) else chain_pem
    certs = x509.load_pem_x509_certificates(pem)
    csr = fetch_csr(client, dev_name)
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if certs[0].public_key().public_bytes(*fmt) != csr.public_key().public_bytes(*fmt):
        raise MetadataError("signed certificate does not match the pending CSR key (wrong leaf or order)")
    client.deploy(_files(dev_name, label or dev_name, key_size, pem))
