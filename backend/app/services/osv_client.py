"""Client for the OSV (Open Source Vulnerabilities) API.

Docs: https://osv.dev/docs/
"""

import httpx
from app.schemas.scan import Dependency, Vulnerability

OSV_API_URL = "https://api.osv.dev/v1/query"


async def query_osv(dep: Dependency) -> list[Vulnerability]:
    """Query OSV for known vulnerabilities affecting a specific package version."""
    payload: dict = {
        "package": {
            "name": dep.name,
            "ecosystem": dep.ecosystem,
        }
    }

    if dep.version:
        payload["version"] = dep.version

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(OSV_API_URL, json=payload)

    if response.status_code != 200:
        return []

    data = response.json()
    vulns_raw = data.get("vulns", [])

    vulnerabilities: list[Vulnerability] = []
    for v in vulns_raw:
        # Extract severity from the database_specific or severity fields
        severity = _extract_severity(v)
        fixed = _extract_fixed_version(v, dep.ecosystem)
        refs = [r.get("url", "") for r in v.get("references", []) if r.get("url")]

        vulnerabilities.append(
            Vulnerability(
                id=v.get("id", ""),
                summary=v.get("summary", "No summary available"),
                details=v.get("details", ""),
                aliases=v.get("aliases", []),
                severity=severity,
                fixed_version=fixed,
                references=refs[:5],  # limit to 5 references
            )
        )

    return vulnerabilities


def _extract_severity(vuln: dict) -> str:
    """Extract a human-readable severity level from OSV vulnerability data."""
    severity_list = vuln.get("severity", [])
    for s in severity_list:
        if s.get("type") == "CVSS_V3":
            score = _cvss_score_from_vector(s.get("score", ""))
            if score is not None:
                if score >= 9.0:
                    return "CRITICAL"
                if score >= 7.0:
                    return "HIGH"
                if score >= 4.0:
                    return "MEDIUM"
                return "LOW"

    # Fallback: check database_specific for severity
    db_specific = vuln.get("database_specific", {})
    if "severity" in db_specific:
        return db_specific["severity"].upper()

    return "UNKNOWN"


def _cvss_score_from_vector(score_or_vector: str) -> float | None:
    """Extract numeric CVSS score. OSV sometimes puts the score directly."""
    try:
        return float(score_or_vector)
    except (ValueError, TypeError):
        return None


def _extract_fixed_version(vuln: dict, ecosystem: str) -> str | None:
    """Find the fixed version for the given ecosystem from the affected ranges."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None
