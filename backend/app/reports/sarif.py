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
        f"{dep.ecosystem}|{dep.name}|{dep.version}|{v.id}".encode()
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


def render_sarif(scan: ScanResponse) -> dict:
    items = findings(scan)
    rules: dict[str, dict] = {}
    for f in items:
        rules.setdefault(f.vuln.id, _rule(f))
    manifest = scan.filename or "requirements.txt"
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
                "results": [_result(f, manifest) for f in items],
                "properties": {
                    "scanId": scan.id,
                    "riskScore": scan.risk_score,
                    "riskLevel": scan.risk_level,
                    "totalDependencies": scan.total_dependencies,
                    "vulnerableDependencies": scan.vulnerable_dependencies,
                },
            }
        ],
    }
