from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .analyze import build_record, parse_certs
from .model import CertRecord, Finding

CERT_EXTS = {".crt", ".pem", ".cer", ".der"}
SF_DEFAULT_ENDPOINTS = ["login.salesforce.com", "test.salesforce.com", "api.salesforce.com"]


# ---------------------------------------------------------------- certificate blobs (files or Metadata API)

def _meta_fields(blob: Optional[bytes]) -> dict:
    """Parse Salesforce <Name>.crt-meta.xml (Certificate metadata)."""
    if not blob:
        return {}
    return {el.tag.split("}")[-1]: (el.text or "").strip() for el in ET.fromstring(blob)}


def records_from_blobs(blobs: dict[str, bytes], source: str) -> list[CertRecord]:
    records: list[CertRecord] = []
    for path in sorted(blobs):
        p = PurePosixPath(path)
        if p.suffix.lower() not in CERT_EXTS:
            continue
        meta = _meta_fields(blobs.get(path + "-meta.xml"))
        label = meta.get("masterLabel") or p.stem
        try:
            certs = parse_certs(blobs[path])
        except Exception as e:
            records.append(CertRecord(source=source, name=label, location=path, error=f"parse error: {e}",
                                      findings=[Finding("PARSE_ERROR", "LOW", str(e))]))
            continue
        extra = {k: v for k, v in meta.items() if k != "masterLabel"}
        extra["dev_name"] = p.stem
        if "caSigned" in extra:
            extra["custom_ca"] = extra["caSigned"].lower() == "true"
        rec = build_record(certs[0], source, label, path, extra)
        if len(certs) > 1:
            rec.extra["chain_len"] = len(certs)
        records.append(rec)
    return records


def scan_files(root: Path) -> list[CertRecord]:
    paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    base = root.parent if root.is_file() else root
    blobs = {p.relative_to(base).as_posix(): p.read_bytes() for p in paths
             if p.suffix.lower() in CERT_EXTS or p.name.endswith(".crt-meta.xml")}
    return records_from_blobs(blobs, "file")


# ---------------------------------------------------------------- live TLS endpoints

def _chain_der(sslsock: ssl.SSLSocket, verified: bool) -> list[bytes]:
    getter = getattr(sslsock, "get_verified_chain" if verified else "get_unverified_chain", None)
    if getter is None:
        return []
    return [c if isinstance(c, (bytes, bytearray)) else c.public_bytes(serialization.Encoding.DER)
            for c in getter() or []]


def _public_ip(host: str, port: int) -> str:
    """Resolve once and refuse non-public addresses (hosted mode must not probe internal networks).
    Connecting to the returned IP also closes the DNS-rebinding window. Set SFDCAUTOCERT_ALLOW_PRIVATE=1 to disable."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if os.environ.get("SFDCAUTOCERT_ALLOW_PRIVATE") == "1":
        return infos[0][4][0]
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise PermissionError(f"{host} resolves to a non-public address ({ip}); not scanned")
    return infos[0][4][0]


def scan_endpoint(host: str, port: int = 443, timeout: float = 8.0) -> CertRecord:
    target = f"{host}:{port}"
    verify_error: Optional[str] = None
    verified = False

    def fail(e):
        sev = "INFO" if isinstance(e, PermissionError) else "MEDIUM"
        code = "NOT_SCANNED" if isinstance(e, PermissionError) else "UNREACHABLE"
        return CertRecord(source="endpoint", name=target, location=target, error=str(e),
                          findings=[Finding(code, sev, str(e) if code == "NOT_SCANNED" else f"TLS handshake failed: {e}")])

    try:
        ip = _public_ip(host, port)
    except (OSError, PermissionError) as e:
        return fail(e)

    try:
        ctx = ssl.create_default_context(cafile=certifi.where())  # Mozilla root set
        with socket.create_connection((ip, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
            verified = True
            chain = _chain_der(ss, True) or [ss.getpeercert(binary_form=True)]
            tls_version, cipher = ss.version(), ss.cipher()[0]
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message
    except (OSError, ssl.SSLError) as e:
        return fail(e)

    if not verified:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
                chain = _chain_der(ss, False) or [ss.getpeercert(binary_form=True)]
                tls_version, cipher = ss.version(), ss.cipher()[0]
        except (OSError, ssl.SSLError) as e:
            return fail(e)

    certs = [x509.load_der_x509_certificate(d) for d in chain]
    top = certs[-1]
    extra = {
        "tls_version": tls_version,
        "cipher": cipher,
        "mozilla_trusted": verified,
        "chain": [c.subject.rfc4514_string() for c in certs],
        "root": (top.subject if top.subject == top.issuer else top.issuer).rfc4514_string(),
    }
    rec = build_record(certs[0], "endpoint", host, target, extra)
    for f in rec.findings:  # third-party server certs: informative, not actionable by the org owner
        if f.code in ("DUAL_USE", "LONG_LIFETIME"):
            f.severity = "INFO"
    if not verified:
        rec.findings.append(Finding("UNTRUSTED_CHAIN", "HIGH",
                                    f"chain does not validate against the Mozilla root set: {verify_error}"))
    return rec


def scan_endpoints(targets: Iterable[str]) -> list[CertRecord]:
    out = []
    for t in targets:
        host, _, port = t.strip().partition(":")
        if host:
            out.append(scan_endpoint(host, int(port) if port else 443))
    return out
