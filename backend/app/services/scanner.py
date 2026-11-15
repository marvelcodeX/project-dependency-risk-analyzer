"""The scan pipeline: parse → OSV lookup → KEV/reachability enrichment → score.

Shared by the HTTP API (which persists the result) and the CLI (which
doesn't). Deliberately free of database and FastAPI imports so the CLI can run
with a minimal install.

Raises ``ManifestError`` for unparseable/unsupported manifests and
``OsvError`` when the vulnerability database is unavailable.
"""

from app.parsers import detect_format, parse_manifest
from app.schemas.scan import DependencyScanResult, ScanResponse, Vulnerability
from app.services import reachability as reach
from app.services import registry
from app.services.kev_client import get_kev_cve_ids
from app.services.osv_client import query_osv_many
from app.services.risk import compute_risk, risk_level


def dedupe_advisories(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Merge advisories that describe the same issue.

    OSV often returns one issue under several databases' ids (e.g. a GHSA and
    a PYSEC entry that list each other, or share a CVE, as aliases). Keep one
    entry per issue, preferring the one with a CVSS score, and fold the other
    ids into its aliases so nothing is lost.
    """
    groups: list[tuple[set[str], list[Vulnerability]]] = []
    for v in vulns:
        ids = {v.id, *v.aliases}
        matches = [g for g in groups if g[0] & ids]
        merged_ids, members = set(ids), [v]
        for g in matches:
            merged_ids |= g[0]
            members.extend(g[1])
            groups.remove(g)
        groups.append((merged_ids, members))

    out: list[Vulnerability] = []
    for ids, members in groups:
        # Prefer a scored entry, then a GHSA (richest metadata), then first seen.
        best = min(
            members,
            key=lambda m: (m.cvss_score is None, not m.id.startswith("GHSA-")),
        )
        if best.fixed_version is None:
            best.fixed_version = next(
                (m.fixed_version for m in members if m.fixed_version), None
            )
        best.aliases = sorted(ids - {best.id})
        # Enrichment from any duplicate counts (e.g. CWEs only on the GHSA).
        best.cwe_ids = sorted(
            {c for m in members for c in m.cwe_ids}, key=lambda c: int(c[4:])
        )
        best.has_public_exploit = any(m.has_public_exploit for m in members)
        out.append(best)
    return out


async def scan_manifest(
    content: str,
    filename: str,
    source_files: dict[str, str] | None = None,
) -> ScanResponse:
    """Scan one manifest and return the scored (unsaved) result."""
    fmt = detect_format(filename, content)
    dependencies = parse_manifest(content, filename)
    # Pasted text arrives without a real name; label it by detected format.
    if not filename or filename == "pasted":
        filename = fmt

    # Unversioned deps (bare "numpy", "*"): scan the version an install would
    # pick today instead of every advisory ever filed for the package.
    await registry.resolve_unversioned(dependencies)

    # Reachability: analyze provided source once per language (Python, JS/TS),
    # then classify every package, propagating through the dependency graph.
    imports = reach.analyze_sources(source_files or {})
    reachability_by_key = reach.classify_all(dependencies, imports)

    # KEV catalog is fetched once (cached) and reused for the whole scan.
    kev_ids = await get_kev_cve_ids()
    all_vulns = await query_osv_many(dependencies)

    results: list[DependencyScanResult] = []
    overall_risk = 0
    for dep, vulns in zip(dependencies, all_vulns):
        vulns = dedupe_advisories(vulns)
        reachability = reachability_by_key[dep.key]
        for v in vulns:
            cve_ids = {a for a in v.aliases if a.startswith("CVE-")}
            if v.id.startswith("CVE-"):
                cve_ids.add(v.id)
            v.in_cisa_kev = bool(cve_ids & kev_ids)
            v.reachability = reachability
            v.risk_score, v.risk_level = compute_risk(
                v, dep, v.in_cisa_kev, reachability
            )
            overall_risk = max(overall_risk, v.risk_score)
        vulns.sort(key=lambda x: x.risk_score, reverse=True)
        results.append(DependencyScanResult(dependency=dep, vulnerabilities=vulns))

    return ScanResponse(
        filename=filename,
        total_dependencies=len(dependencies),
        vulnerable_dependencies=sum(1 for r in results if r.vulnerabilities),
        risk_score=overall_risk,
        risk_level=risk_level(overall_risk),
        results=results,
    )
