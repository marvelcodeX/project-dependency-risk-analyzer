"""Self-contained, printable HTML report (Print → Save as PDF for a PDF).

No scripts and no external assets, so it renders the same offline, in email
attachments, and when printed. All advisory text is HTML-escaped: it comes from
external vulnerability databases and must be treated as untrusted.
"""

from collections import Counter
from html import escape

from app import __version__
from app.reports.common import RISK_ORDER, findings, normalized_severity, osv_url
from app.schemas.scan import ScanResponse

_REACH_LABEL = {
    "REACHABLE": "Imported",
    "UNREACHABLE": "Not imported",
    "POTENTIALLY_REACHABLE": "Possibly",
    "UNKNOWN": "Unknown",
}

_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1d24; --muted: #5b6270; --line: #e3e6eb;
  --panel: #f6f7f9; --critical: #b4232f; --high: #c2570c; --medium: #a16207;
  --low: #2563a6; --none: #5b6270; --ok: #15803d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1218; --fg: #e6e8ec; --muted: #9aa1ad; --line: #262b35;
    --panel: #161a22; --critical: #f87171; --high: #fb923c; --medium: #fbbf24;
    --low: #60a5fa; --none: #9aa1ad; --ok: #4ade80;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 8px; }
.meta { color: var(--muted); font-size: 13px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin-top: 20px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 14px; }
.card b { display: block; font-size: 24px; font-variant-numeric: tabular-nums; }
.card span { color: var(--muted); font-size: 12px; text-transform: uppercase;
  letter-spacing: .04em; }
.kev { margin-top: 16px; padding: 10px 14px; border-radius: 8px;
  border: 1px solid var(--critical); color: var(--critical); font-weight: 600; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; white-space: nowrap; }
td.num { font-variant-numeric: tabular-nums; font-weight: 700; white-space: nowrap; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
a { color: var(--low); }
.lvl-CRITICAL { color: var(--critical); } .lvl-HIGH { color: var(--high); }
.lvl-MEDIUM { color: var(--medium); } .lvl-LOW { color: var(--low); }
.lvl-NONE, .lvl-UNKNOWN { color: var(--none); }
.ok { color: var(--ok); font-weight: 600; }
footer { margin-top: 32px; color: var(--muted); font-size: 12px; }
@media print {
  :root { --bg: #fff; --fg: #000; --panel: #fff; --line: #ccc; }
  main { max-width: none; padding: 0; }
  tr { break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"""


def render_html(scan: ScanResponse) -> str:
    items = findings(scan)
    e = escape
    when = scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "—"
    by_risk = Counter(f.vuln.risk_level for f in items)
    kev = sum(1 for f in items if f.vuln.in_cisa_kev)

    cards = [
        (f'<b class="lvl-{e(scan.risk_level)}">{scan.risk_score}</b>',
         f"Risk · {e(scan.risk_level)}"),
        (f"<b>{scan.total_dependencies}</b>", "Dependencies"),
        (f"<b>{scan.vulnerable_dependencies}</b>", "Vulnerable"),
        (f"<b>{len(items)}</b>", "Findings"),
    ] + [
        (f'<b class="lvl-{lvl}">{by_risk[lvl]}</b>', lvl.title())
        for lvl in RISK_ORDER[:4]
    ]
    cards_html = "".join(
        f'<div class="card">{value}<span>{label}</span></div>' for value, label in cards
    )

    if items:
        rows = []
        for f in items:
            v = f.vuln
            sev = normalized_severity(v)
            cvss = f" {v.cvss_score}" if v.cvss_score is not None else ""
            cves = ", ".join(f.cve_ids)
            kev_cell = '<b class="lvl-CRITICAL">Yes</b>' if v.in_cisa_kev else "No"
            rows.append(
                "<tr>"
                f'<td class="num lvl-{e(v.risk_level)}">{v.risk_score}</td>'
                f"<td><code>{e(f.package_label)}</code><br>"
                f'<span class="meta">{e(f.dep.ecosystem)}</span></td>'
                f'<td><a href="{e(osv_url(v.id))}">{e(v.id)}</a>'
                + (f'<br><span class="meta">{e(cves)}</span>' if cves else "")
                + "</td>"
                f'<td class="lvl-{sev}">{sev}{e(cvss)}</td>'
                f"<td>{e(v.fixed_version) if v.fixed_version else '—'}</td>"
                f"<td>{kev_cell}</td>"
                f"<td>{e(_REACH_LABEL.get(v.reachability, v.reachability))}</td>"
                f"<td>{e(v.summary)}</td>"
                "</tr>"
            )
        table = (
            '<div class="table-wrap"><table><thead><tr>'
            "<th>Risk</th><th>Package</th><th>Advisory</th><th>Severity</th>"
            "<th>Fixed in</th><th>KEV</th><th>Reachable</th><th>Summary</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
        )
    else:
        table = '<p class="ok">No known vulnerabilities found.</p>'

    kev_html = (
        f'<div class="kev">{kev} finding(s) are actively exploited in the wild '
        "(CISA Known Exploited Vulnerabilities).</div>"
        if kev
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Soteria-AI Report</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>Dependency risk report</h1>
<div class="meta"><code>{e(scan.filename)}</code> · scan #{e(str(scan.id))} · {e(when)}</div>
<div class="cards">{cards_html}</div>
{kev_html}
<h2>Findings</h2>
{table}
<footer>Generated by Soteria-AI {e(__version__)}. Risk score (0–100) = CVSS (40)
+ exploited in the wild (25) + reachability (20) + no fix available (10)
+ version exposure (5). Vulnerability data: OSV.dev, CISA KEV.</footer>
</main>
</body>
</html>
"""
