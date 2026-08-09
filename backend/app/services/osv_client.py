"""Client for the OSV (Open Source Vulnerabilities) API.

Docs: https://osv.dev/docs/
"""

import httpx
from app.schemas.scan import Dependency, Vulnerability
from app.services.cvss import base_score_from_vector, severity_label

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
        # Extract severity from the severity vector or database_specific fields
        severity, cvss_score, cvss_vector = _extract_severity(v)
        fixed = _extract_fixed_version(v, dep.ecosystem)
        refs = [r.get("url", "") for r in v.get("references", []) if r.get("url")]

        vulnerabilities.append(
            Vulnerability(
                id=v.get("id", ""),
                summary=v.get("summary", "No summary available"),
                details=v.get("details", ""),
                aliases=v.get("aliases", []),
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                fixed_version=fixed,
                references=refs[:5],  # limit to 5 references
            )
        )

    return vulnerabilities


def _extract_severity(vuln: dict) -> tuple[str, float | None, str | None]:
    """Derive a severity level, numeric CVSS score, and vector from OSV data.

    OSV puts the CVSS *vector string* in ``severity[].score`` (not a number),
    so we compute the base score from it. Prefers CVSS v3.1, then v3.0.
    Returns ``(level, score, vector)``.
    """
    severity_list = vuln.get("severity", [])
    # Prefer the newest CVSS 3.x vector we can actually score.
    for wanted in ("CVSS_V3",):
        for s in severity_list:
            if s.get("type") != wanted:
                continue
            vector = s.get("score", "")
            score = base_score_from_vector(vector)
            if score is not None:
                return severity_label(score), score, vector

    # Fallback: some databases (e.g. GitHub advisories) put a qualitative
    # rating in database_specific instead of a CVSS vector.
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific.get("severity"), str):
        return db_specific["severity"].upper(), None, None

    return "UNKNOWN", None, None


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
