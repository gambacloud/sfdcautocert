"""Find the external endpoints an org depends on and TLS-scan them."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePosixPath
from urllib.parse import urlparse

from typing import Callable

from . import limits, sources
from .model import CertRecord, Finding

ENDPOINT_TYPES = ["RemoteSiteSetting", "CspTrustedSite"]  # in addition to usage.TYPES
URL_TAGS = {"url", "endpoint", "endpointUrl", "authorizeUrl", "tokenUrl", "userInfoUrl", "loginUrl", "sslConnectionUrl"}
FOLDER_LABEL = {
    "remoteSiteSettings": "RemoteSiteSetting", "cspTrustedSites": "CspTrustedSite", "namedCredentials": "NamedCredential",
    "dataSources": "ExternalDataSource", "authproviders": "AuthProvider", "classes": "Apex", "triggers": "Apex",
    "flows": "Flow",
}
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+")
_IGNORE_HOSTS = ("sforce.com", "w3.org", "xmlsoap.org", "localhost", "127.0.0.1", "example.com", "example.org")


def extract_endpoints(blobs: dict[str, bytes]) -> dict[tuple[str, str, int], set[str]]:
    """{(scheme, host, port): {referencing components}}"""
    found: dict[tuple[str, str, int], set[str]] = {}

    def add(raw: str, ref: str):
        raw = raw.strip().rstrip(".,;'\"")
        u = urlparse(raw)
        host = u.hostname
        if u.scheme not in ("http", "https") or not host or "." not in host:
            return
        if any(host == h or host.endswith("." + h) for h in _IGNORE_HOSTS):
            return
        port = u.port or (443 if u.scheme == "https" else 80)
        found.setdefault((u.scheme, host, port), set()).add(ref)

    for path, data in blobs.items():
        p = PurePosixPath(path)
        label = FOLDER_LABEL.get(p.parts[0]) if p.parts else None
        if not label or p.name.endswith("-meta.xml") and label == "Apex":
            continue
        ref = f"{label}:{p.name.split('.')[0]}"
        text = data.decode("utf-8", "replace")
        if p.suffix in (".cls", ".trigger", ".flow"):
            for m in _URL_RE.findall(text):
                add(m, ref)
        else:
            try:
                for el in ET.fromstring(data).iter():
                    if el.tag.split("}")[-1] in URL_TAGS and el.text:
                        add(el.text, ref)
            except ET.ParseError:
                pass
    return found


def scan_discovered(blobs: dict[str, bytes], timeout: float = 8.0, workers: int = 12,
                    max_hosts: int = limits.MAX_ENDPOINT_SCANS, note: Callable[[str], None] = lambda m: None) -> list[CertRecord]:
    found = sorted(extract_endpoints(blobs).items())
    refs_of = {}
    for (scheme, host, port), refs in found:
        if scheme == "https":
            refs_of.setdefault((host, port), set()).update(refs)
    # configuration references first (they are what Salesforce actually calls), then the most referenced
    ranked = sorted(refs_of, key=lambda hp: (all(r.startswith(("Apex:", "Flow:")) for r in refs_of[hp]), -len(refs_of[hp]), hp))
    tls_hosts = sorted(ranked[:max_hosts])
    if len(ranked) > max_hosts:
        note(f"Endpoint scan limited to {max_hosts} of {len(ranked)} hosts referenced by the org")
        found = [f for f in found if f[0][0] != "https" or (f[0][1], f[0][2]) in set(tls_hosts)]
    with ThreadPoolExecutor(max_workers=workers) as pool:  # unreachable hosts only cost one timeout, in parallel
        scanned = dict(zip(tls_hosts, pool.map(lambda hp: sources.scan_endpoint(hp[0], hp[1], timeout), tls_hosts)))

    records: list[CertRecord] = []
    refs_by_host: dict[tuple[str, int], set[str]] = {}
    for (scheme, host, port), refs in found:
        if scheme == "https":
            refs_by_host.setdefault((host, port), set()).update(refs)
        else:
            records.append(CertRecord(
                source="endpoint", name=f"{host}:{port}", location=f"{scheme}://{host}:{port}",
                extra={"scheme": "http", "referenced_by": sorted(refs)},
                findings=[Finding("NO_TLS", "LOW", "plain HTTP endpoint referenced by the org")]))
    for hp, rec in scanned.items():
        rec.extra["referenced_by"] = sorted(refs_by_host[hp])
        rec.extra["scheme"] = "https"
        records.append(rec)
    return records
