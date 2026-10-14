"""Triage: which certificates / endpoints actually matter for the Salesforce certificate changes.

Levels (highest first):
  ACTION        affected by the announced changes or about to break - needs work
  WATCH         customer-managed, public-CA based or integration-critical; fine today
  CLEANUP       unused/expired leftover; remove after verifying
  NOT_AFFECTED  Salesforce-managed, or self-signed/private CA (explicitly out of scope of the public-CA changes)
"""
from __future__ import annotations

from .model import CertRecord

LEVELS = ["NOT_AFFECTED", "CLEANUP", "WATCH", "ACTION"]


def rank(level: str) -> int:
    return LEVELS.index(level)


def classify(rec: CertRecord) -> tuple[str, str]:
    codes = {f.code: f.severity for f in rec.findings}

    if rec.source == "endpoint":
        if "NOT_SCANNED" in codes:
            return "NOT_AFFECTED", "internal/non-public address - not scanned from this service"
        if rec.error:
            return "ACTION", "TLS handshake failed - integration may already be broken"
        if "UNTRUSTED_CHAIN" in codes:
            return "ACTION", "chain not valid against the Mozilla root set (needs custom CA in trust store or a re-issue)"
        if rec.extra.get("scheme") == "http":
            return "WATCH", "plain HTTP endpoint (no TLS)"
        return "NOT_AFFECTED", f"publicly trusted chain, root: {rec.extra.get('root', '?')}"

    if rec.extra.get("system_managed"):
        return "NOT_AFFECTED", "Salesforce-managed certificate (rotated by Salesforce)"

    public_ca = not rec.self_signed and rec.extra.get("custom_ca", False) is False and rec.extra.get("ca_signed", False)
    if codes.get("DUAL_USE") == "CRITICAL":
        return "ACTION", "dual-use EKU on a public-CA certificate (serverAuth+clientAuth)"
    if "WEAK_KEY" in codes or "WEAK_SIG" in codes:
        return "ACTION", "weak key/signature algorithm"
    used = bool(rec.usages)
    d = rec.days_left
    if used and d is not None and d <= 20:
        return "ACTION", f"in use and {'expired' if d < 0 else f'expires in {d} days'}"
    if not used and (d is not None and d < 0):
        return "CLEANUP", "expired and no references found in scanned metadata"
    if not used:
        return "CLEANUP", "no references found in scanned metadata (verify org-level use first)"
    if public_ca:
        return "WATCH", "CA-signed and in use - subject to shorter public-CA lifetimes"
    top = max(rec.usages, key=lambda u: u.weight)
    return "NOT_AFFECTED", f"self-signed/private CA, used by {top.kind}"
