from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

SEVERITIES = ["OK", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class Finding:
    code: str
    severity: str
    message: str


@dataclass
class Usage:
    kind: str          # SamlSsoConfig, NamedCredential, ConnectedApp, ApexClass, ...
    component: str     # component full name
    detail: str        # how the cert is referenced
    confidence: str    # exact | pem | text
    weight: int        # blast-radius weight 0-100


@dataclass
class CertRecord:
    source: str  # salesforce | file | endpoint
    name: str
    location: str = ""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_left: Optional[int] = None
    validity_days: Optional[int] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    sig_alg: Optional[str] = None
    eku: list[str] = field(default_factory=list)
    san: list[str] = field(default_factory=list)
    self_signed: bool = False
    is_ca: bool = False
    sha256: Optional[str] = None
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    usages: list[Usage] = field(default_factory=list)
    relevance: str = ""
    relevance_reason: str = ""

    @property
    def severity(self) -> str:
        return max((f.severity for f in self.findings), key=sev_rank, default="OK")

    @property
    def risk_score(self) -> int:
        """0-100: urgency (time left / findings) scaled by blast radius (most critical usage)."""
        d = self.days_left
        urgency = 10 if d is None else 100 if d < 0 else 90 if d < 10 else 60 if d <= 20 else 30 if d <= 47 else 10
        if any(f.code in ("DUAL_USE", "WEAK_KEY", "WEAK_SIG") and f.severity in ("CRITICAL", "HIGH") for f in self.findings):
            urgency = max(urgency, 80)
        weight = max((u.weight for u in self.usages), default=20)
        return round(urgency * max(weight, 20) / 100)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "name": self.name,
            "location": self.location,
            "severity": self.severity,
            "days_left": self.days_left,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "validity_days": self.validity_days,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "sig_alg": self.sig_alg,
            "eku": self.eku,
            "san": self.san,
            "self_signed": self.self_signed,
            "is_ca": self.is_ca,
            "sha256": self.sha256,
            "error": self.error,
            "extra": self.extra,
            "relevance": self.relevance,
            "relevance_reason": self.relevance_reason,
            "risk_score": self.risk_score,
            "findings": [vars(f) for f in self.findings],
            "usages": [vars(u) for u in self.usages],
        }
