"""SARIF 2.1.0 output, suitable for GitHub code scanning upload.

One rule per advisory, one result per (dependency, advisory). Result level
follows the *composite* risk level (so KEV/reachability are reflected), while
the rule's ``security-severity`` carries the raw CVSS score that GitHub uses
for its own severity badges.
"""

import hashlib

from app import __version__
from app.reports.common import (
    TOOL_NAME,
    TOOL_URI,
    Finding,
    findings,
    normalized_severity,
    osv_url,
)
from app.schemas.scan import ScanResponse

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Fallback security-severity when an advisory has no CVSS score.
_SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0}

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}


def _rule(f: Finding) -> dict:
    v = f.vuln
    sev = normalized_severity(v)
    score = v.cvss_score if v.cvss_score is not None else _SEVERITY_SCORE.get(sev)
    props: dict = {"tags": ["security", "dependency", f.dep.ecosystem]}
    if score is not None:
        props["security-severity"] = f"{score:.1f}"
    help_uri = v.references[0] if v.references else osv_url(v.id)
    return {
        "id": v.id,
        "name": v.id.replace("-", ""),
        "shortDescription": {"text": v.summary or v.id},
        "fullDescription": {"text": (v.details or v.summary or v.id)[:4000]},
        "helpUri": help_uri,
        "help": {
            "text": f"{v.summary}\n\nDetails: {osv_url(v.id)}",
            "markdown": f"**{v.id}** — {v.summary}\n\n[View on OSV]({osv_url(v.id)})",
        },
        "properties": props,
    }


def _result(f: Finding, manifest: str) -> dict:
    v, dep = f.vuln, f.dep
    fix = f"Upgrade to {v.fixed_version}." if v.fixed_version else "No fixed version published yet."
    kev = " Actively exploited in the wild (CISA KEV)." if v.in_cisa_kev else ""
    fingerprint = hashlib.sha256(
        f"{manifest}|{dep.ecosystem}|{dep.name}|{dep.version}|{v.id}".encode()
    ).hexdigest()
    return {
        "ruleId": v.id,
        "level": _LEVEL.get(v.risk_level, "note"),
        "message": {
            "text": f"{f.package_label} is affected by {v.id}: "
            f"{(v.summary or 'no summary').rstrip('.')}. {fix}{kev}"
        },
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": manifest}},
                "logicalLocations": [
                    {"name": dep.name, "kind": "package",
                     "fullyQualifiedName": f"{dep.ecosystem}/{dep.name}"}
                ],
            }
        ],
        "partialFingerprints": {"soteriaFinding/v1": fingerprint},
        "properties": {
            "package": dep.name,
            "version": dep.version,
            "ecosystem": dep.ecosystem,
            "fixedVersion": v.fixed_version,
            "cveIds": f.cve_ids,
            "riskScore": v.risk_score,
            "riskLevel": v.risk_level,
            "inCisaKev": v.in_cisa_kev,
            "reachability": v.reachability,
        },
    }


def render_sarif(scans: ScanResponse | list[ScanResponse]) -> dict:
    """Render one or more scans as a single SARIF run.

    Each scan's manifest becomes the location of its results, so a CI scan of
    several manifests uploads as one run (GitHub code scanning rejects multiple
    runs from the same tool and category in one file).
    """
    if isinstance(scans, ScanResponse):
        scans = [scans]
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for scan in scans:
        manifest = scan.filename or "requirements.txt"
        for f in findings(scan):
            rules.setdefault(f.vuln.id, _rule(f))
            results.append(_result(f, manifest))
    results.sort(key=lambda r: -r["properties"]["riskScore"])

    worst = max(scans, key=lambda s: s.risk_score, default=None)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "scanIds": [s.id for s in scans if s.id is not None],
                    "manifests": [s.filename for s in scans],
                    "riskScore": worst.risk_score if worst else 0,
                    "riskLevel": worst.risk_level if worst else "NONE",
                    "totalDependencies": sum(s.total_dependencies for s in scans),
                    "vulnerableDependencies": sum(
                        s.vulnerable_dependencies for s in scans
                    ),
                },
            }
        ],
    }
