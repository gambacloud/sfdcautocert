"""Tooling API (REST) query, server-side."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

from .. import limits
from .auth import Session


def query(session: Session, soql: str, api_version: str = "62.0") -> list[dict]:
    url = f"{session.instance_url}/services/data/v{api_version}/tooling/query?q={urllib.parse.quote(soql)}"
    records: list[dict] = []
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {session.access_token}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read(limits.MAX_JSON_RESPONSE + 1)
        if len(raw) > limits.MAX_JSON_RESPONSE:
            raise ValueError(f"Tooling API page larger than {limits.MAX_JSON_RESPONSE // (1024 * 1024)} MB")
        page = json.loads(raw)
        records += page.get("records", [])
        nxt = page.get("nextRecordsUrl")
        url = session.instance_url + nxt if nxt else None
    return records


def certificate_flags(session: Session, api_version: str = "62.0") -> dict[str, dict]:
    """DeveloperName -> flags (system managed, CA signed, key exportable)."""
    rows = query(session, "SELECT DeveloperName, OptionsIsCaSigned, OptionsIsSystemManaged, "
                          "OptionsIsPrivateKeyExportable FROM Certificate", api_version)
    return {r["DeveloperName"]: {"ca_signed": bool(r["OptionsIsCaSigned"]),
                                 "system_managed": bool(r["OptionsIsSystemManaged"]),
                                 "key_exportable": bool(r["OptionsIsPrivateKeyExportable"])} for r in rows}
