"""Orchestration layer: collectors -> analysis -> inventory. Used by both the CLI and the web backend.

Layers (each can grow independently):
  sf/        Salesforce clients (auth, Metadata API, Tooling API) - the only code that talks to Salesforce
  collectors sources.py (certs/files/TLS), usage.py (cert -> component mapping), discovery.py (endpoints)
  analysis   analyze.py (findings), relevance.py (triage)
  service    this module: scan_org(), Inventory (cached snapshot + refresh)
  web.py     JSON API + dashboard
  actions    certstore.py / rotate.py / acme.py / issue.py  (phase 2: issuance & rotation)
"""
from __future__ import annotations

import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, Optional

from . import apex, discovery, relevance, sources, usage
from .model import CertRecord
from .sf import tooling
from .sf.auth import Session
from .sf.metadata import MetadataClient


def scan_org(session: Session, api_version: str = "62.0", scope: str = "standard", with_usage: bool = True,
             with_endpoints: bool = True, log: Callable[[str], None] = lambda m: print(m, file=sys.stderr),
             note: Callable[[str], None] = lambda m: None) -> list[CertRecord]:
    """scope: standard (config metadata only) | apex (+ relevant Apex) | all (+ Apex, settings, sites, networks)."""
    client = MetadataClient(session, api_version)
    blobs = client.retrieve("Certificate")
    records = sources.records_from_blobs(blobs, "salesforce")
    try:
        flags = tooling.certificate_flags(session, api_version)
        for r in records:
            r.extra.update(flags.get(r.extra.get("dev_name"), {}))
    except Exception as e:  # Tooling API is an enrichment, not required
        log(f"Tooling API flags unavailable: {e}")
    apex_scanned = with_usage and scope in ("apex", "all")
    for r in records:
        r.extra["apex_scanned"] = apex_scanned
    if with_usage:
        pems = {p: b.decode("ascii", "replace") for p, b in blobs.items() if p.lower().endswith(".crt")}
        types = usage.metadata_types(scope) + discovery.ENDPOINT_TYPES
        comp_blobs, warns = usage.collect(client, types)
        for w in warns:
            log(f"could not retrieve {w}")
        if apex_scanned:
            names = [n for r in records for n in (r.extra.get("dev_name"), r.name)]
            try:
                apex_blobs, st = apex.scan_apex(session, names, api_version)
                comp_blobs.update(apex_blobs)
                note(f"Apex: scanned {st['scanned']} classes/triggers, {st['relevant']} relevant "
                     f"({st['managed_skipped']} managed-package skipped)")
            except Exception as e:
                log(f"Apex scan failed: {e}")
                for r in records:
                    r.extra["apex_scanned"] = False
        usage.map_usages(records, comp_blobs, pems)
        if with_endpoints:
            records += discovery.scan_discovered(comp_blobs)
    for r in records:
        r.relevance, r.relevance_reason = relevance.classify(r)
    return records


def summarize(records: list[CertRecord]) -> dict:
    certs = [r for r in records if r.source != "endpoint"]
    eps = [r for r in records if r.source == "endpoint"]
    return {
        "certificates": len(certs),
        "endpoints": len(eps),
        "by_relevance": dict(Counter(r.relevance for r in records)),
        "expiring_20d": sum(1 for r in certs if r.days_left is not None and 0 <= r.days_left <= 20),
        "expired": sum(1 for r in certs if r.days_left is not None and r.days_left < 0),
        "dual_use": sum(1 for r in records if any(f.code == "DUAL_USE" and f.severity == "CRITICAL" for f in r.findings)),
        "unused": sum(1 for r in certs if any(f.code == "UNUSED" for f in r.findings)),
    }


class Inventory:
    """Thread-safe cached snapshot of the org; `refresh()` re-scans using a fresh session each time."""

    def __init__(self, session_factory: Callable[[], Session], org_label: str = "", scope: str = "standard", **scan_kwargs):
        self._factory, self._kw, self.org_label = session_factory, scan_kwargs, org_label
        self._lock = threading.Lock()
        self._records: list[CertRecord] = []
        self.scope = scope               # scope of the running / last scan
        self.scanned_at: Optional[datetime] = None
        self.duration: Optional[float] = None
        self.error: Optional[str] = None
        self.warnings: list[str] = []
        self.notes: list[str] = []
        self.scanning = False

    def refresh(self, scope: Optional[str] = None) -> None:
        with self._lock:
            if self.scanning:
                return
            self.scanning = True
            if scope:
                self.scope = scope
            run_scope = self.scope
        t0 = time.time()
        try:
            warns: list[str] = []
            notes: list[str] = []
            records = scan_org(self._factory(), scope=run_scope, log=warns.append, note=notes.append, **self._kw)
            with self._lock:
                self._records, self.error, self.warnings, self.notes = records, None, warns, notes
                self.scanned_at, self.duration = datetime.now(timezone.utc), round(time.time() - t0, 1)
        except Exception as e:
            with self._lock:
                self.error = f"{type(e).__name__}: {e}"
        finally:
            with self._lock:
                self.scanning = False

    def refresh_async(self, scope: Optional[str] = None) -> None:
        threading.Thread(target=self.refresh, args=(scope,), daemon=True).start()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "org": self.org_label,
                "scope": self.scope,
                "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
                "duration_s": self.duration,
                "scanning": self.scanning,
                "error": self.error,
                "warnings": list(self.warnings),
                "notes": list(self.notes),
                "summary": summarize(self._records),
                "items": [r.to_dict() for r in self._records],
            }
