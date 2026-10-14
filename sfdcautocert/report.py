from __future__ import annotations

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .model import CertRecord, sev_rank
from .relevance import rank as rel_rank


def _sorted(records: list[CertRecord]) -> list[CertRecord]:
    return sorted(records, key=lambda r: (-rel_rank(r.relevance or 'NOT_AFFECTED'), -r.risk_score, -sev_rank(r.severity), r.days_left if r.days_left is not None else 10**6))


def console(records: list[CertRecord]) -> str:
    rows = _sorted(records)
    if not rows:
        return "No certificates found."
    lines = [f"{'RELEVANCE':<13}{'SEV':<9}{'RISK':>5}{'DAYS':>7}  {'NAME':<34}{'USES':>5}  FINDINGS"]
    lines.append("-" * 100)
    for r in rows:
        days = "-" if r.days_left is None else str(r.days_left)
        codes = ",".join(f.code for f in r.findings) or "-"
        lines.append(f"{(r.relevance or '-'):<13}{r.severity:<9}{r.risk_score:>5}{days:>7}  {r.name[:33]:<34}{len(r.usages):>5}  {codes}")
        if r.relevance_reason:
            lines.append(f"{'':<13}{'':<9}{'':>5}{'':>7}    why: {r.relevance_reason}")
        for ref in r.extra.get("referenced_by", []):
            lines.append(f"{'':<13}{'':<9}{'':>5}{'':>7}    <- {ref}")
        for u in r.usages:
            lines.append(f"{'':<13}{'':<9}{'':>5}{'':>7}    -> {u.kind}: {u.component} ({u.detail}, {u.confidence})")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    lines.append("-" * 100)
    lines.append("Total %d | " % len(rows) + " ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: -sev_rank(kv[0]))))
    return "\n".join(lines)


def write_json(records: list[CertRecord], path: Path) -> None:
    payload = {"generated": datetime.now(timezone.utc).isoformat(), "certificates": [r.to_dict() for r in _sorted(records)]}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(records: list[CertRecord], path: Path) -> None:
    cols = ["relevance", "relevance_reason", "severity", "days_left", "not_after", "source", "name", "location", "issuer", "key_type", "key_size",
            "sig_alg", "eku", "self_signed", "risk_score", "used_by", "findings"]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in _sorted(records):
            d = r.to_dict()
            w.writerow([d["relevance"], d["relevance_reason"], d["severity"], d["days_left"], d["not_after"], d["source"], d["name"], d["location"],
                        d["issuer"], d["key_type"], d["key_size"], d["sig_alg"], "|".join(d["eku"]),
                        d["self_signed"], d["risk_score"],
                        "; ".join(f"{u['kind']}:{u['component']}" for u in d["usages"]), "; ".join(f"{x['code']}: {x['message']}" for x in d["findings"])])


_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CertPulse</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--card:#f6f6f7;--g:#2e7d32;--y:#b7791f;--r:#c62828}
@media(prefers-color-scheme:dark){:root{--bg:#141414;--fg:#eee;--mut:#999;--card:#1f1f21;--g:#66bb6a;--y:#f0b429;--r:#ef5350}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:16px}
.kpis{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.kpi{background:var(--card);padding:10px 16px;border-radius:8px}
.kpi b{font-size:22px;display:block}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--card);vertical-align:top}
th{color:var(--mut);font-weight:500}.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;color:#fff}
.g{background:var(--g)}.y{background:var(--y)}.r{background:var(--r)}.n{background:var(--mut)}
.f{color:var(--mut);font-size:12px}.wrap{overflow-x:auto}
</style></head><body><h1>CertPulse</h1><div class="sub">Generated __TS__</div>
<div class="kpis">__KPIS__</div><div class="wrap"><table><thead><tr><th>Relevance</th><th>Days left</th><th>Risk</th><th>Severity</th><th>Name</th><th>Source</th>
<th>Issuer</th><th>Key / EKU</th><th>Used by</th><th>Findings</th></tr></thead><tbody>__ROWS__</tbody></table></div></body></html>"""


def write_html(records: list[CertRecord], path: Path) -> None:
    rows, red, yellow, dual = [], 0, 0, 0
    for r in _sorted(records):
        d = r.days_left
        cls = "n" if d is None else "r" if d < 10 else "y" if d <= 20 else "g"
        red += cls == "r"
        yellow += cls == "y"
        dual += any(f.code == "DUAL_USE" and f.severity == "CRITICAL" for f in r.findings)
        findings = "<br>".join(f"<b>{html.escape(f.code)}</b> <span class=f>{html.escape(f.message)}</span>" for f in r.findings) or "-"
        used = "<br>".join(f"{html.escape(u.kind)}: <b>{html.escape(u.component)}</b> <span class=f>{html.escape(u.detail)}</span>"
                           for u in r.usages) or "-"
        key = f"{r.key_type or '-'} {r.key_size or ''}<br><span class=f>{html.escape(','.join(r.eku) or 'no EKU')}</span>"
        rows.append(
            f"<tr><td><b>{r.relevance or '-'}</b><br><span class=f>{html.escape(r.relevance_reason)}</span></td><td><span class='pill {cls}'>{'n/a' if d is None else d}</span></td><td>{r.risk_score}</td><td>{r.severity}</td>"
            f"<td>{html.escape(r.name)}<br><span class=f>{html.escape(r.location)}</span></td><td>{r.source}</td>"
            f"<td class=f>{html.escape(r.issuer or '-')}</td><td>{key}</td><td>{used}</td><td>{findings}</td></tr>")
    kpis = "".join(f"<div class=kpi><b>{v}</b>{k}</div>" for k, v in
                   [("certificates", len(records)), ("red (<10d)", red), ("yellow (10-20d)", yellow), ("dual-use (critical)", dual)])
    path.write_text(_HTML.replace("__TS__", datetime.now().strftime("%Y-%m-%d %H:%M")).replace("__KPIS__", kpis)
                    .replace("__ROWS__", "".join(rows)), encoding="utf-8")
