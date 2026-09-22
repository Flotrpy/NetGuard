"""Security report generation (HTML, PDF, JSON, CSV).

Reports never contain secrets: scanners already redact values, and every string that goes into a
report additionally passes through :func:`scrub`, which masks anything matching a provider-specific
secret pattern (defence in depth).
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from jinja2 import Environment, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard import __version__
from netguard.enums import ACTIVE_STATUSES, DETECTION_SOURCE_LABELS, Scanner, Severity
from netguard.models import Asset, Finding, NetworkHost, Patch, Project, Repository, Scan
from netguard.scanners.registry import scanner_infos
from netguard.scanners.secrets.patterns import RULES as SECRET_RULES
from netguard.scanners.secrets.util import redact
from netguard.services.risk import METHODOLOGY, severity_counts

SEVERITY_ORDER = [s.value for s in Severity]
FORMATS = ("html", "pdf", "json", "csv")
MAX_FINDINGS = 2000


def scrub(text: str) -> str:
    """Mask anything that looks like a real credential."""
    if not text:
        return text
    for rule in SECRET_RULES:
        if rule.generic:
            continue

        def mask(m, rule=rule):  # noqa: ANN001
            value = m.group(rule.group) if rule.group else m.group(0)
            return m.group(0).replace(value, redact(value, rule.prefix)) if value else m.group(0)

        text = rule.pattern.sub(mask, text)
    return text


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    return value


def build_report_data(
    db: Session,
    project: Project,
    *,
    title: str = "",
    min_severity: str = "info",
    scanners: list[str] | None = None,
    include_fixed: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    floor = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else len(SEVERITY_ORDER) - 1
    query = select(Finding).where(Finding.project_id == project.id)
    if scanners:
        query = query.where(Finding.scanner.in_(scanners))
    rows = [f for f in db.scalars(query) if SEVERITY_ORDER.index(f.severity) <= floor]
    active_values = {s.value for s in ACTIVE_STATUSES}
    if not include_fixed:
        rows = [f for f in rows if f.status in active_values]
    rows.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), -f.risk_score, f.title))
    truncated = len(rows) > MAX_FINDINGS
    rows = rows[:MAX_FINDINGS]

    patches = {p.finding_id: p for p in db.scalars(
        select(Patch).where(Patch.finding_id.in_([f.id for f in rows] or [""])).order_by(Patch.created_at))}
    assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.project_id == project.id))}
    findings = [{
        "id": f.id, "title": f.title, "severity": f.severity, "confidence": f.confidence,
        "risk_score": f.risk_score, "status": f.status, "source": DETECTION_SOURCE_LABELS.get(
            Scanner(f.scanner), f.scanner) if f.scanner in {s.value for s in Scanner} else f.scanner,
        "scanner": f.scanner, "rule_id": f.rule_id, "cwe": f.cwe, "category": f.category,
        "location": (f"{f.file_path}:{f.line}" if f.file_path and f.line else f.file_path
                     or (assets[f.asset_id].name if f.asset_id in assets else "")),
        "asset": assets[f.asset_id].name if f.asset_id in assets else "",
        "description": f.description, "impact": f.impact, "remediation": f.remediation,
        "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
        "verification": f.verification,
        "patch": ({"status": patches[f.id].status, "generator": patches[f.id].generator,
                   "verification": (patches[f.id].verification or {}).get("state", "")}
                  if f.id in patches else None),
        "package": ({"name": (f.extra or {}).get("package"), "version": (f.extra or {}).get("version"),
                     "fixed": ((f.extra or {}).get("fixed_versions") or [""])[0],
                     "ecosystem": (f.extra or {}).get("ecosystem"),
                     "advisory": (f.extra or {}).get("vulnerability")} if f.scanner == "dependencies" else None),
        "network": ({"ip": (f.extra or {}).get("ip"), "port": (f.extra or {}).get("port"),
                     "service": (f.extra or {}).get("service")} if f.scanner in ("network", "packets") else None),
    } for f in rows]

    active = [f for f in findings if f["status"] in active_values]
    fixed = [f for f in findings if f["status"] == "fixed"]
    verified = [f for f in findings if f["verification"] == "verified_fixed"]
    scans = db.scalars(select(Scan).where(Scan.project_id == project.id)
                       .order_by(Scan.created_at.desc()).limit(15)).all()
    repos = db.scalars(select(Repository).where(Repository.project_id == project.id)).all()
    hosts = db.scalars(select(NetworkHost).where(NetworkHost.project_id == project.id)
                       .order_by(NetworkHost.scanned_at.desc())).all()
    latest_hosts: dict[str, NetworkHost] = {}
    for h in hosts:
        latest_hosts.setdefault(h.ip, h)
    by_scanner: dict[str, int] = {}
    for f in active:
        by_scanner[f["source"]] = by_scanner.get(f["source"], 0) + 1
    denominator = len(active) + len(fixed)
    data = {
        "title": title.strip() or f"Security Assessment: {project.name}",
        "generated_at": now.isoformat(),
        "netguard_version": __version__,
        "project": {"id": project.id, "name": project.name, "description": project.description},
        "scope": {
            "repositories": [{"name": r.name, "provider": r.provider, "url": r.url} for r in repos],
            "network_hosts": len(latest_hosts),
            "assets": len(assets),
            "scan_count": len(scans),
            "filters": {"min_severity": min_severity, "scanners": scanners or "all",
                        "include_fixed": include_fixed},
        },
        "methodology": {
            "detect_explain_fix_verify": "Findings come from deterministic detection rules, OSV.dev "
            "advisories or passive network observations; none are invented by AI. A fix is only "
            "'verified' after a rescan no longer detects the issue.",
            "scanners": [{"name": i.display_name, "version": i.version, "available": i.available,
                          "description": i.description} for i in scanner_infos()],
            "risk": METHODOLOGY,
        },
        "summary": {
            "severity": severity_counts([f["severity"] for f in active]),
            "active": len(active), "fixed": len(fixed), "verified_fixed": len(verified),
            "total_findings": len(findings), "by_source": by_scanner,
            "remediation_progress": round(len(fixed) / denominator, 3) if denominator else None,
            "truncated": truncated,
        },
        "findings": findings,
        "verification": [f for f in findings if f["verification"] != "none" or f["patch"]],
        "dependencies": [f for f in findings if f["package"]],
        "network": {
            "hosts": [{"ip": h.ip, "hostname": h.hostname, "device_type": h.device_type,
                       "ports": sorted(s.port for s in h.services)} for h in latest_hosts.values()],
            "findings": [f for f in findings if f["network"]],
        },
        "scan_history": [{"id": s.id, "kind": s.kind, "status": s.status,
                          "scanners": s.scanners, "started": s.created_at.isoformat()} for s in scans],
    }
    return _clean(data)


# ---- renderers ----------------------------------------------------------------------------------
def to_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def _csv_cell(v: Any) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(data: dict[str, Any]) -> bytes:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["severity", "title", "status", "confidence", "risk_score", "source", "location", "cwe",
                "rule_id", "first_seen", "last_seen", "verification", "remediation"])
    for f in data["findings"]:
        w.writerow([_csv_cell(x) for x in (
            f["severity"], f["title"], f["status"], f["confidence"], f["risk_score"], f["source"],
            f["location"], f["cwe"], f["rule_id"], f["first_seen"], f["last_seen"], f["verification"],
            f["remediation"])])
    return out.getvalue().encode("utf-8-sig")


_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{{ d.title }}</title>
<style>
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a;max-width:980px;margin:2rem auto;padding:0 1rem}
h1{font-size:26px;margin-bottom:0}h2{margin-top:2rem;border-bottom:2px solid #e2e8f0;padding-bottom:.25rem}
.muted{color:#64748b}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.tile{border:1px solid #e2e8f0;border-radius:8px;padding:10px}.tile b{font-size:24px;display:block}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #e2e8f0;padding:6px;text-align:left;vertical-align:top}
.sev{display:inline-block;padding:1px 8px;border-radius:4px;font-weight:600;font-size:12px}
.critical{background:#fee2e2;color:#991b1b}.high{background:#ffedd5;color:#9a3412}.medium{background:#fef9c3;color:#854d0e}
.low{background:#e0f2fe;color:#075985}.info{background:#f1f5f9;color:#475569}
.finding{border:1px solid #e2e8f0;border-radius:8px;padding:12px;margin:12px 0;page-break-inside:avoid}
code{background:#f1f5f9;padding:1px 4px;border-radius:3px}
</style></head><body>
<h1>{{ d.title }}</h1>
<p class="muted">Project: {{ d.project.name }} &middot; Generated {{ d.generated_at }} &middot; NetGuard {{ d.netguard_version }}</p>

<h2>1. Summary</h2>
<div class="grid">{% for s in order %}<div class="tile"><span class="sev {{ s }}">{{ s|title }}</span><b>{{ d.summary.severity[s] }}</b>open</div>{% endfor %}</div>
<p>{{ d.summary.active }} active, {{ d.summary.fixed }} fixed ({{ d.summary.verified_fixed }} verified by rescan) of {{ d.summary.total_findings }} findings.
{% if d.summary.remediation_progress is not none %}Remediation progress (share of actionable findings fixed): {{ (d.summary.remediation_progress * 100)|round|int }}%. This is a progress measure, not a security score.{% endif %}
{% if d.summary.truncated %}<br><b>Note:</b> the report lists only the first {{ d.findings|length }} findings.{% endif %}</p>
{% if d.summary.by_source %}<p>Active findings by source: {% for k, v in d.summary.by_source.items() %}{{ k }} ({{ v }}){{ ", " if not loop.last }}{% endfor %}.</p>{% endif %}

<h2>2. Scope</h2>
<p>Repositories: {% if d.scope.repositories %}{% for r in d.scope.repositories %}{{ r.name }}{{ ", " if not loop.last }}{% endfor %}{% else %}none{% endif %}.
Network hosts inventoried: {{ d.scope.network_hosts }}. Assets tracked: {{ d.scope.assets }}.
Filters: minimum severity {{ d.scope.filters.min_severity }}, scanners {{ d.scope.filters.scanners }}, fixed findings {{ "included" if d.scope.filters.include_fixed else "excluded" }}.</p>

<h2>3. Methodology</h2>
<p>{{ d.methodology.detect_explain_fix_verify }}</p>
<table><tr><th>Scanner</th><th>Version</th><th>Available</th></tr>
{% for s in d.methodology.scanners %}<tr><td>{{ s.name }}</td><td>{{ s.version }}</td><td>{{ "yes" if s.available else "planned" }}</td></tr>{% endfor %}</table>
<p class="muted">Risk score: {{ d.methodology.risk.formula }}. {% for n in d.methodology.risk.notes %}{{ n }} {% endfor %}</p>

<h2>4. Findings</h2>
{% for f in d.findings %}
<div class="finding">
<span class="sev {{ f.severity }}">{{ f.severity|title }}</span> <b>{{ f.title }}</b>
<div class="muted">{{ f.source }} &middot; {{ f.status }} &middot; confidence {{ f.confidence }} &middot; risk {{ "%.1f"|format(f.risk_score) }}{% if f.cwe %} &middot; {{ f.cwe }}{% endif %}{% if f.location %} &middot; <code>{{ f.location }}</code>{% endif %}</div>
{% if f.description %}<p>{{ f.description }}</p>{% endif %}
{% if f.impact %}<p><b>Impact:</b> {{ f.impact }}</p>{% endif %}
{% if f.remediation %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}
{% if f.verification != "none" %}<p><b>Verification:</b> {{ f.verification|replace("_", " ") }}</p>{% endif %}
</div>{% else %}<p>No findings match the selected filters.</p>{% endfor %}

<h2>5. Verification results</h2>
{% if d.verification %}<table><tr><th>Finding</th><th>Patch</th><th>Result</th></tr>
{% for f in d.verification %}<tr><td>{{ f.title }}</td><td>{{ f.patch.generator ~ " / " ~ f.patch.status if f.patch else "n/a" }}</td><td>{{ f.verification|replace("_", " ") }}</td></tr>{% endfor %}</table>
{% else %}<p>No fixes have been verified yet.</p>{% endif %}

<h2>6. Dependency information</h2>
{% if d.dependencies %}<table><tr><th>Package</th><th>Version</th><th>Severity</th><th>Advisory</th><th>Fixed in</th></tr>
{% for f in d.dependencies %}<tr><td>{{ f.package.name }} ({{ f.package.ecosystem }})</td><td>{{ f.package.version }}</td><td>{{ f.severity }}</td><td>{{ f.package.advisory }}</td><td>{{ f.package.fixed or "none published" }}</td></tr>{% endfor %}</table>
{% else %}<p>No dependency findings.</p>{% endif %}

<h2>7. Network</h2>
{% if d.network.hosts %}<table><tr><th>Host</th><th>Device</th><th>Open ports</th></tr>
{% for h in d.network.hosts %}<tr><td>{{ h.hostname or h.ip }} ({{ h.ip }})</td><td>{{ h.device_type }}</td><td>{{ h.ports|join(", ") }}</td></tr>{% endfor %}</table>
{% else %}<p>No network inventory available.</p>{% endif %}

<h2>8. Recent scans</h2>
<table><tr><th>When</th><th>Kind</th><th>Scanners</th><th>Status</th></tr>
{% for s in d.scan_history %}<tr><td>{{ s.started }}</td><td>{{ s.kind }}</td><td>{{ s.scanners|join(", ") }}</td><td>{{ s.status }}</td></tr>{% endfor %}</table>
<p class="muted">Secret values are never included in reports. This report reflects automated tooling and should be reviewed by a qualified person.</p>
</body></html>"""

_env = Environment(autoescape=select_autoescape(["html"], default_for_string=True), trim_blocks=True, lstrip_blocks=True)


def to_html(data: dict[str, Any]) -> bytes:
    return _env.from_string(_HTML).render(d=data, order=SEVERITY_ORDER).encode("utf-8")


def to_pdf(data: dict[str, Any]) -> bytes:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=8.5, leading=11)
    esc = lambda s: escape(str(s or ""))  # noqa: E731
    story: list[Any] = [Paragraph(esc(data["title"]), styles["Title"]),
                        Paragraph(f"Project: {esc(data['project']['name'])} &middot; Generated "
                                  f"{esc(data['generated_at'][:19])} UTC &middot; NetGuard {esc(data['netguard_version'])}",
                                  small), Spacer(1, 8)]
    sm = data["summary"]
    story += [Paragraph("1. Summary", styles["Heading2"])]
    tiles = [["Critical", "High", "Medium", "Low", "Info"], [str(sm["severity"][s]) for s in SEVERITY_ORDER]]
    t = Table(tiles, hAlign="LEFT")
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                           ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story += [t, Spacer(1, 6), Paragraph(
        f"{sm['active']} active, {sm['fixed']} fixed ({sm['verified_fixed']} verified by rescan) of "
        f"{sm['total_findings']} findings. Remediation progress is a progress measure, not a security score.",
        styles["BodyText"])]
    story += [Paragraph("2. Scope", styles["Heading2"]), Paragraph(
        f"Repositories: {esc(', '.join(r['name'] for r in data['scope']['repositories']) or 'none')}. "
        f"Network hosts inventoried: {data['scope']['network_hosts']}. Assets tracked: {data['scope']['assets']}.",
        styles["BodyText"])]
    story += [Paragraph("3. Methodology", styles["Heading2"]),
              Paragraph(esc(data["methodology"]["detect_explain_fix_verify"]), styles["BodyText"]),
              Paragraph(esc(data["methodology"]["risk"]["formula"]), small)]
    story += [Paragraph("4. Findings", styles["Heading2"])]
    rows = [["Severity", "Finding", "Source", "Status", "Location"]]
    for f in data["findings"][:500]:
        rows.append([f["severity"].title(), Paragraph(esc(f["title"]), small), Paragraph(esc(f["source"]), small),
                     f["status"].replace("_", " "), Paragraph(esc(f["location"]), small)])
    ft = Table(rows, colWidths=[18 * mm, 68 * mm, 30 * mm, 22 * mm, 42 * mm], repeatRows=1)
    ft.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                            ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [ft]
    for f in data["findings"][:100]:
        story += [Spacer(1, 6), Paragraph(f"<b>{esc(f['severity'].title())}</b>: {esc(f['title'])}", styles["Heading4"]),
                  Paragraph(esc(f["description"]), small),
                  Paragraph(f"<b>Impact:</b> {esc(f['impact'])}", small),
                  Paragraph(f"<b>Remediation:</b> {esc(f['remediation'])}", small)]
    story += [Paragraph("5. Verification results", styles["Heading2"])]
    if data["verification"]:
        for f in data["verification"]:
            story.append(Paragraph(f"{esc(f['title'])}: {esc(f['verification'].replace('_', ' '))}", small))
    else:
        story.append(Paragraph("No fixes have been verified yet.", small))
    story += [Paragraph("6. Dependency information", styles["Heading2"])]
    for f in data["dependencies"][:100]:
        p = f["package"]
        story.append(Paragraph(f"{esc(p['name'])} {esc(p['version'])} ({esc(p['ecosystem'])}): {esc(p['advisory'])}, "
                               f"fixed in {esc(p['fixed'] or 'none published')}", small))
    story += [Paragraph("7. Network", styles["Heading2"])]
    for h in data["network"]["hosts"][:100]:
        story.append(Paragraph(f"{esc(h['hostname'] or h['ip'])} ({esc(h['ip'])}): ports "
                               f"{esc(', '.join(map(str, h['ports'])) or 'none')}", small))
    story.append(Paragraph("Secret values are never included in reports.", small))
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                      title=data["title"], author="NetGuard").build(story)
    return buf.getvalue()


RENDERERS = {"html": (to_html, "text/html; charset=utf-8"), "json": (to_json, "application/json"),
             "csv": (to_csv, "text/csv; charset=utf-8"), "pdf": (to_pdf, "application/pdf")}
