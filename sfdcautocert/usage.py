"""Map certificates to the org components that depend on them.

Three evidence types, strongest first:
  exact - an XML element's text equals the certificate's DeveloperName/label
  pem   - the certificate's PEM body is embedded in a component (e.g. Connected App JWT cert)
  text  - the DeveloperName appears as a whole token in source (Apex setClientCertificateName, etc.)
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

from .model import CertRecord, Finding, Usage
from .sf.metadata import MetadataClient, MetadataError

# metadata type -> blast-radius weight (0-100)
TYPES = {
    "SamlSsoConfig": 100,       # SAML SSO
    "ConnectedApp": 80,
    "NamedCredential": 70,      # outbound callouts / mTLS
    "ExternalCredential": 70,
    "AuthProvider": 70,
    "ExternalDataSource": 50,
    "ApexClass": 50,
    "ApexTrigger": 50,
    "Flow": 60,                 # HTTP callout / external service actions
    "Settings": 40,             # org-wide settings (Identity Provider, My Domain, ...)
    "CustomSite": 40,           # Experience Cloud / Sites
    "Network": 40,              # Experience Cloud networks
}

# Scan scopes. standard = configuration only (default); apex = + relevant Apex only; all = + sites/networks.
# Settings is cheap and holds the Identity Provider certificate, so it is part of the default scan.
CONFIG_TYPES = ["SamlSsoConfig", "ConnectedApp", "NamedCredential", "ExternalCredential", "AuthProvider",
                "ExternalDataSource", "Flow", "Settings"]
EXTRA_TYPES = ["CustomSite", "Network"]
# specific components that matter more than their type's default weight
COMPONENT_WEIGHTS = {("Settings", "IdentityProvider"): 100}
SCOPES = ("standard", "apex", "all")


def metadata_types(scope: str) -> list[str]:
    """Metadata API types to retrieve for a scope (Apex is scanned separately, see apex.py)."""
    if scope not in SCOPES:
        raise ValueError(f"unknown scope {scope!r}")
    return CONFIG_TYPES + (EXTRA_TYPES if scope == "all" else [])
# mdapi folder -> metadata type
FOLDERS = {
    "samlssoconfigs": "SamlSsoConfig", "connectedApps": "ConnectedApp", "namedCredentials": "NamedCredential",
    "externalCredentials": "ExternalCredential", "authproviders": "AuthProvider",
    "dataSources": "ExternalDataSource", "classes": "ApexClass", "triggers": "ApexTrigger",
    "flows": "Flow", "settings": "Settings", "sites": "CustomSite", "networks": "Network",
}
_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)


def collect(client: MetadataClient, types=TYPES, workers: int = 4) -> tuple[dict[str, bytes], list[str]]:
    """Retrieve each type separately (in parallel) so one unsupported/empty type doesn't fail the rest."""
    types = list(types)

    def one(t: str):
        try:
            return t, client.retrieve(t), None
        except MetadataError as e:
            return t, {}, str(e)

    blobs: dict[str, bytes] = {}
    warnings: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for t, got, err in pool.map(one, types):
            blobs.update(got)
            if err:
                warnings.append(f"{t}: {err}")
    return blobs, warnings


def _squash(s: str) -> str:
    return re.sub(r"\s+", "", s)


def map_usages(records: list[CertRecord], blobs: dict[str, bytes], pems: dict[str, str] | None = None) -> None:
    """Populate rec.usages (and an UNUSED finding) for every Salesforce certificate record.
    pems: {certificate path -> PEM text}, used for embedded-certificate matching."""
    comps = []  # (type, name, [(tag, text)], raw text)
    for path, data in blobs.items():
        p = PurePosixPath(path)
        ctype = FOLDERS.get(p.parts[0]) if p.parts else None
        if not ctype or p.name.endswith("-meta.xml"):
            continue
        text = data.decode("utf-8", "replace")
        fields: list[tuple[str, str]] = []
        if p.suffix not in (".cls", ".trigger"):
            try:
                fields = [(el.tag.split("}")[-1], el.text.strip()) for el in ET.fromstring(data).iter()
                          if el.text and el.text.strip()]
            except ET.ParseError:
                pass
        comps.append((ctype, p.name.split(".")[0], fields, text))

    for rec in records:
        if rec.source != "salesforce":
            continue
        names = {n for n in (rec.extra.get("dev_name"), rec.name) if n}
        pem_body = ""
        for m in _PEM_RE.findall((pems or {}).get(rec.location, "")):
            pem_body = _squash(m)
            break
        seen = set()
        for ctype, cname, fields, text in comps:
            def add(detail, conf):
                if (ctype, cname) not in seen:
                    seen.add((ctype, cname))
                    rec.usages.append(Usage(ctype, cname, detail, conf, COMPONENT_WEIGHTS.get((ctype, cname), TYPES[ctype])))

            hit = next((tag for tag, val in fields if val in names), None)
            if hit:
                add(f"field <{hit}>", "exact")
            elif pem_body and any(_squash(m) == pem_body for m in _PEM_RE.findall(text)):
                add("embedded certificate (PEM match)", "pem")
            elif any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(n)}(?![A-Za-z0-9_])", text) for n in names):
                add("referenced in source", "text")
        if not rec.usages:
            rec.findings.append(Finding(
                "UNUSED", "LOW",
                "no references found in scanned metadata types; verify org-level use (Identity Provider, My Domain) before removing"))
