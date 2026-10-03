"""CycloneDX 1.5 JSON SBOM with embedded vulnerabilities.

Every scanned dependency becomes a component (identified by purl); each
advisory becomes one vulnerability entry whose ``affects`` lists every
component it hits. Soteria's own signals (composite risk, KEV, reachability)
are carried as ``soteria:*`` properties rather than as a VEX ``analysis``:
import-level reachability is a heuristic, and stating ``not_affected`` would
let downstream tools silently suppress a real finding.
"""

import uuid
from datetime import datetime, timezone

from app import __version__
from app.reports.common import (
    TOOL_NAME,
    TOOL_URI,
    component_ref,
    findings,
    normalized_severity,
    osv_url,
    purl,
)
from app.schemas.scan import ScanResponse, Vulnerability

SPEC_VERSION = "1.5"


def _rating(v: Vulnerability) -> dict:
    rating: dict = {"source": {"name": "OSV", "url": osv_url(v.id)}}
    sev = normalized_severity(v)
    rating["severity"] = "info" if sev == "NONE" else sev.lower()
    if v.cvss_score is not None:
        rating["score"] = v.cvss_score
    if v.cvss_vector:
        rating["vector"] = v.cvss_vector
        rating["method"] = (
            "CVSSv31" if v.cvss_vector.upper().startswith("CVSS:3.1") else "CVSSv3"
        )
    return rating


def render_cyclonedx(scan: ScanResponse) -> dict:
    components: dict[str, dict] = {}
    for r in scan.results:
        ref = component_ref(r.dependency)
        if ref in components:
            continue
        comp: dict = {
            "type": "library",
            "bom-ref": ref,
            "name": r.dependency.name,
        }
        if r.dependency.version:
            comp["version"] = r.dependency.version
        if p := purl(r.dependency):
            comp["purl"] = p
        comp["properties"] = [
            {"name": "soteria:ecosystem", "value": r.dependency.ecosystem},
            {"name": "soteria:pinned", "value": str(r.dependency.pinned).lower()},
            {"name": "soteria:declared_spec", "value": r.dependency.raw_spec},
        ]
        components[ref] = comp

    vulns: dict[str, dict] = {}
    for f in findings(scan):
        v = f.vuln
        ref = component_ref(f.dep)
        entry = vulns.get(v.id)
        if entry is None:
            entry = {
                "bom-ref": f"vuln:{v.id}",
                "id": v.id,
                "source": {"name": "OSV", "url": osv_url(v.id)},
                "ratings": [_rating(v)],
                "description": v.summary,
                "properties": [],
                "affects": [],
            }
            if v.details:
                entry["detail"] = v.details
            refs = [
                {
                    "id": cve,
                    "source": {
                        "name": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    },
                }
                for cve in f.cve_ids
                if cve != v.id
            ]
            if refs:
                entry["references"] = refs
            if v.references:
                entry["advisories"] = [{"url": u} for u in v.references]
            if v.fixed_version:
                entry["recommendation"] = f"Upgrade to {v.fixed_version} or later."
            vulns[v.id] = entry

        entry["affects"].append({"ref": ref})
        # Per-component signals (risk differs by version/reachability).
        entry["properties"].extend(
            [
                {"name": f"soteria:risk_score:{ref}", "value": str(v.risk_score)},
                {"name": f"soteria:risk_level:{ref}", "value": v.risk_level},
                {"name": f"soteria:reachability:{ref}", "value": v.reachability},
            ]
        )
        if v.in_cisa_kev and not any(
            p["name"] == "soteria:cisa_kev" for p in entry["properties"]
        ):
            entry["properties"].append({"name": "soteria:cisa_kev", "value": "true"})

    timestamp = (scan.created_at or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": TOOL_NAME,
                        "version": __version__,
                        "externalReferences": [{"type": "website", "url": TOOL_URI}],
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "soteria:project",
                "name": scan.filename or "project",
            },
            "properties": [
                {"name": "soteria:scan_id", "value": str(scan.id)},
                {"name": "soteria:risk_score", "value": str(scan.risk_score)},
                {"name": "soteria:risk_level", "value": scan.risk_level},
            ],
        },
        # No "dependencies" graph: lockfile scans mix direct and transitive
        # packages, and we don't know which is which.
        "components": list(components.values()),
        "vulnerabilities": list(vulns.values()),
    }
