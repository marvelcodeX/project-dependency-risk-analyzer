"""Markdown report — pasteable into a PR comment, issue or ticket."""

from collections import Counter

from app.reports.common import RISK_ORDER, findings, normalized_severity, osv_url
from app.schemas.scan import ScanResponse

_REACH_LABEL = {
    "REACHABLE": "imported",
    "UNREACHABLE": "not imported",
    "POTENTIALLY_REACHABLE": "possibly",
    "UNKNOWN": "unknown",
}


def _cell(text: str | None) -> str:
    """Make advisory text safe inside a table cell (it's untrusted input)."""
    if not text:
        return ""
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def render_markdown(scan: ScanResponse) -> str:
    items = findings(scan)
    when = scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "—"
    lines = [
        f"# Soteria-AI dependency report — `{_cell(scan.filename)}`",
        "",
        f"**Project risk: {scan.risk_score}/100 ({scan.risk_level})** · "
        f"{scan.vulnerable_dependencies} of {scan.total_dependencies} dependencies "
        f"vulnerable · {len(items)} findings · scanned {when}",
        "",
    ]

    if not items:
        lines.append("✅ No known vulnerabilities found.")
        return "\n".join(lines) + "\n"

    by_risk = Counter(f.vuln.risk_level for f in items)
    kev = sum(1 for f in items if f.vuln.in_cisa_kev)
    lines.append(
        "| Risk level | Findings |\n|---|---:|\n"
        + "\n".join(f"| {lvl} | {by_risk[lvl]} |" for lvl in RISK_ORDER if by_risk[lvl])
    )
    if kev:
        lines += ["", f"🚨 **{kev} finding(s) are actively exploited in the wild (CISA KEV).**"]

    lines += [
        "",
        "## Findings",
        "",
        "| Risk | Package | Advisory | Severity | Fix | KEV | Reachable | Summary |",
        "|---:|---|---|---|---|:-:|---|---|",
    ]
    for f in items:
        v = f.vuln
        cvss = f" ({v.cvss_score})" if v.cvss_score is not None else ""
        lines.append(
            f"| {v.risk_score} {v.risk_level} "
            f"| `{_cell(f.package_label)}` "
            f"| [{_cell(v.id)}]({osv_url(v.id)}) "
            f"| {normalized_severity(v)}{cvss} "
            f"| {_cell(v.fixed_version) or '—'} "
            f"| {'🚨' if v.in_cisa_kev else ''} "
            f"| {_REACH_LABEL.get(v.reachability, v.reachability)} "
            f"| {_cell(v.summary)} |"
        )
    lines += [
        "",
        "_Risk = CVSS (40) + exploited in the wild (25) + reachability (20) + "
        "no fix (10) + version exposure (5)._",
    ]
    return "\n".join(lines) + "\n"
