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

_ENCODING_DER = getattr(getattr(ssl, "_ssl", None), "ENCODING_DER", 2)


def _chain_der(sslsock: ssl.SSLSocket, verified: bool) -> list[bytes]:
    """Peer chain as DER. SSLSocket.get_*_chain is public from Python 3.13; on 3.10-3.12 only the private
    SSLObject methods exist (they return _ssl.Certificate objects)."""
    name = "get_verified_chain" if verified else "get_unverified_chain"
    getter = getattr(sslsock, name, None) or getattr(getattr(sslsock, "_sslobj", None), name, None)
    if getter is None:
        return []
    try:
        chain = getter() or []
    except (ValueError, OSError):
        return []
    return [bytes(c) if isinstance(c, (bytes, bytearray)) else c.public_bytes(_ENCODING_DER) for c in chain]


# OpenSSL verify codes we report specifically; anything else is an untrusted chain
_HOSTNAME_CODES = {62, 64}      # hostname / IP address mismatch (the chain itself validated)
_EXPIRED_CODE = 10
_NOT_YET_VALID_CODE = 9


def _public_ips(host: str, port: int) -> list[str]:
    """Resolve once and refuse non-public addresses (hosted mode must not probe internal networks).
    Connecting to the returned IPs (not the name) also closes the DNS-rebinding window.
    Set SFDCAUTOCERT_ALLOW_PRIVATE=1 to disable the check."""
    ips = list(dict.fromkeys(i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if os.environ.get("SFDCAUTOCERT_ALLOW_PRIVATE") != "1":
        for ip in ips:
            if not ipaddress.ip_address(ip).is_global:
                raise PermissionError(f"{host} resolves to a non-public address ({ip}); not scanned")
    return ips


def _connect(ips: list[str], port: int, timeout: float) -> socket.socket:
    """create_connection semantics over pre-resolved addresses: first one that answers wins."""
    err: Optional[Exception] = None
    for ip in ips:
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            err = e
    raise err or OSError("no address to connect to")


def scan_endpoint(host: str, port: int = 443, timeout: float = 8.0, cafile: Optional[str] = None) -> CertRecord:
    target = f"{host}:{port}"
    verify_error: Optional[str] = None
    verify_code: Optional[int] = None
    verified = False

    def fail(e):
        sev = "INFO" if isinstance(e, PermissionError) else "MEDIUM"
        code = "NOT_SCANNED" if isinstance(e, PermissionError) else "UNREACHABLE"
        return CertRecord(source="endpoint", name=target, location=target, error=str(e),
                          findings=[Finding(code, sev, str(e) if code == "NOT_SCANNED" else f"TLS handshake failed: {e}")])

    try:
        ips = _public_ips(host, port)
    except (OSError, PermissionError) as e:
        return fail(e)

    try:
        ctx = ssl.create_default_context(cafile=cafile or certifi.where())  # Mozilla root set
        with _connect(ips, port, timeout) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
            verified = True
            chain = _chain_der(ss, True) or [ss.getpeercert(binary_form=True)]
            tls_version, cipher = ss.version(), ss.cipher()[0]
    except ssl.SSLCertVerificationError as e:
        verify_error, verify_code = e.verify_message, e.verify_code
    except (OSError, ssl.SSLError) as e:
        return fail(e)

    if not verified:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with _connect(ips, port, timeout) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
                chain = _chain_der(ss, False) or [ss.getpeercert(binary_form=True)]
                tls_version, cipher = ss.version(), ss.cipher()[0]
        except (OSError, ssl.SSLError) as e:
            return fail(e)

    certs = [x509.load_der_x509_certificate(d) for d in chain]
    top = certs[-1]
    extra = {
        "tls_version": tls_version,
        "cipher": cipher,
        # a hostname mismatch is only reported after the chain itself validated
        "mozilla_trusted": verified or verify_code in _HOSTNAME_CODES,
        "verify_error": verify_error,
        "verify_code": verify_code,
        "chain": [c.subject.rfc4514_string() for c in certs],
        "root": (top.subject if top.subject == top.issuer else top.issuer).rfc4514_string(),
    }
    rec = build_record(certs[0], "endpoint", host, target, extra)
    for f in rec.findings:  # third-party server certs: informative, not actionable by the org owner
        if f.code in ("DUAL_USE", "LONG_LIFETIME", "EXPIRES_SOON"):
            f.severity = "INFO"
    if not verified:
        if verify_code in _HOSTNAME_CODES:
            rec.findings.append(Finding(
                "HOSTNAME_MISMATCH", "MEDIUM",
                f"the certificate is not valid for {host} (the chain itself is trusted) - callouts to this host fail; "
                "the reference may be stale or point to a retired host"))
        elif verify_code == _EXPIRED_CODE:
            pass  # already reported as EXPIRED by the certificate analysis
        elif verify_code == _NOT_YET_VALID_CODE:
            rec.findings.append(Finding("NOT_YET_VALID", "MEDIUM", "the certificate is not valid yet"))
        else:
            rec.findings.append(Finding(
                "UNTRUSTED_CHAIN", "HIGH",
                f"chain does not validate against the Mozilla root set ({verify_error}). Salesforce's own trust store "
                "may differ - check whether a custom CA is uploaded before acting"))
    return rec


def scan_endpoints(targets: Iterable[str]) -> list[CertRecord]:
    out = []
    for t in targets:
        host, _, port = t.strip().partition(":")
        if host:
            out.append(scan_endpoint(host, int(port) if port else 443))
    return out
