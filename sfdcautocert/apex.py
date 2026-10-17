"""Bounded Apex scan.

Apex bodies cannot be filtered server-side (`Body` is not filterable in SOQL and is not in the SOSL index),
and a wildcard Metadata API retrieve downloads and holds every class. Instead we list classes cheaply,
pull bodies in small batches through the Tooling API, and keep only the ones that matter for
certificates / outbound calls. Bodies that do not match are dropped immediately, so memory stays flat.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable

from . import limits
from .sf import tooling
from .sf.auth import Session

# Apex is case-insensitive, so everything is compared lowercased.
MARKERS = (
    "setclientcertificatename", "callout:", "auth.jws", "auth.jwt", "crypto.sign",
    "httprequest", "setendpoint", "https://", "http://", "@restresource", "webservice ",
)
KINDS = (("ApexClass", "classes", ".cls"), ("ApexTrigger", "triggers", ".trigger"))
BATCH = 25


def is_relevant(body: str, cert_names: Iterable[str]) -> bool:
    low = body.lower()
    return any(m in low for m in MARKERS) or any(n.lower() in low for n in cert_names if n)


def scan_apex(session: Session, cert_names: Iterable[str], api_version: str = "62.0",
              workers: int = 4) -> tuple[dict[str, bytes], dict[str, int]]:
    """Returns ({'classes/Foo.cls': body, ...} for relevant code only, stats)."""
    names = [n for n in cert_names if n]
    blobs: dict[str, bytes] = {}
    stats = {"scanned": 0, "relevant": 0, "managed_skipped": 0, "truncated": 0}
    retained = 0

    def fetch(kind: str, ids: list[str]) -> list[tuple[str, str]]:
        quoted = ",".join(f"'{i}'" for i in ids)
        rows = tooling.query(session, f"SELECT Name, Body FROM {kind} WHERE Id IN ({quoted})", api_version)
        return [(r["Name"], r.get("Body") or "") for r in rows]

    for kind, folder, ext in KINDS:
        rows = tooling.query(session, f"SELECT Id, NamespacePrefix FROM {kind}", api_version)
        ids = [r["Id"] for r in rows if not r.get("NamespacePrefix")]  # managed package bodies are hidden anyway
        stats["managed_skipped"] += len(rows) - len(ids)
        room = max(limits.MAX_APEX_SCANNED - stats["scanned"] - 0, 0)
        if len(ids) > room:
            stats["truncated"] += len(ids) - room
            ids = ids[:room]
        batches = [ids[i:i + BATCH] for i in range(0, len(ids), BATCH)]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(lambda b: fetch(kind, b), batches):
                for name, body in result:
                    stats["scanned"] += 1
                    if is_relevant(body, names):
                        data = body.encode("utf-8")
                        if retained + len(data) > limits.MAX_APEX_RETAINED:
                            stats["truncated"] += 1
                            continue
                        retained += len(data)
                        stats["relevant"] += 1
                        blobs[f"{folder}/{name}{ext}"] = data
    return blobs, stats
