"""Client for the OSV (Open Source Vulnerabilities) API.

Docs: https://osv.dev/docs/
"""

import asyncio

import httpx
from app.schemas.scan import Dependency, Vulnerability
from app.services.cvss import base_score_from_vector, severity_label
from app.services.versions import less_than

OSV_API_URL = "https://api.osv.dev/v1/query"

# Cap concurrent OSV requests so large manifests don't hammer the API.
_MAX_CONCURRENCY = 10
# Safety stop for pagination (OSV pages are large; this is effectively "all").
_MAX_PAGES = 20


class OsvError(RuntimeError):
    """Raised when OSV can't be reached or returns a server error.

    A security scan must not silently report "no vulnerabilities" because the
    database was down, so callers should surface this rather than swallow it.
    """


async def query_osv(
    dep: Dependency, client: httpx.AsyncClient | None = None
) -> list[Vulnerability]:
    """Query OSV for known vulnerabilities affecting a specific package version.

    Raises ``OsvError`` on network failures or 5xx responses. A 4xx (e.g. a
    version string OSV can't interpret) is treated as "no data" for that dep.
    """
    if client is None:
        async with httpx.AsyncClient(timeout=30.0) as own_client:
            return await query_osv(dep, own_client)

    payload: dict = {"package": {"name": dep.name, "ecosystem": dep.ecosystem}}
    if dep.version:
        payload["version"] = dep.version

    vulns_raw: list[dict] = []
    for _ in range(_MAX_PAGES):
        try:
            response = await client.post(OSV_API_URL, json=payload)
        except httpx.HTTPError as exc:
            raise OsvError(f"OSV request failed for {dep.name}: {exc}") from exc
        if response.status_code >= 500:
            raise OsvError(
                f"OSV returned {response.status_code} for {dep.name}"
            )
        if response.status_code != 200:
            return []
        try:
            data = response.json()
        except ValueError as exc:
            raise OsvError(f"OSV returned invalid JSON for {dep.name}") from exc

        vulns_raw.extend(data.get("vulns", []))
        token = data.get("next_page_token")
        if not token:
            break
        payload["page_token"] = token

    vulnerabilities: list[Vulnerability] = []
    for v in vulns_raw:
        severity, cvss_score, cvss_vector = _extract_severity(v)
        fixed = _extract_fixed_version(v, dep)
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


async def query_osv_many(deps: list[Dependency]) -> list[list[Vulnerability]]:
    """Query OSV for many dependencies concurrently over one HTTP client.

    Returns results in the same order as ``deps``. Raises ``OsvError`` if any
    lookup fails (partial results would understate risk).
    """
    sem = asyncio.Semaphore(_MAX_CONCURRENCY)
    async with httpx.AsyncClient(timeout=30.0) as client:

        async def _one(dep: Dependency) -> list[Vulnerability]:
            async with sem:
                return await query_osv(dep, client)

        return list(await asyncio.gather(*(_one(d) for d in deps)))


def _extract_severity(vuln: dict) -> tuple[str, float | None, str | None]:
    """Derive a severity level, numeric CVSS score, and vector from OSV data.

    OSV puts the CVSS *vector string* in ``severity[].score`` (not a number),
    so we compute the base score from it. Only CVSS v3.x vectors are scored.
    Returns ``(level, score, vector)``.
    """
    for s in vuln.get("severity", []):
        if s.get("type") != "CVSS_V3":
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


def _norm_name(name: str, ecosystem: str) -> str:
    n = name.strip().lower()
    if ecosystem.lower() == "pypi":
        n = n.replace("-", "_").replace(".", "_")
    return n


def _extract_fixed_version(vuln: dict, dep: Dependency) -> str | None:
    """Pick the fixed version relevant to the dependency's installed version.

    An advisory can have several affected ranges (one per release branch), so
    the first ``fixed`` event isn't necessarily the right upgrade target. We
    walk each ``[introduced, fixed)`` interval and return the fix for the one
    containing ``dep.version``. Without a usable match (e.g. no version known)
    we return the highest fixed version, which is safe for every branch.
    """
    eco = dep.ecosystem
    want = _norm_name(dep.name, eco)
    fixes: list[str] = []
    containing: str | None = None

    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != eco.lower():
            continue
        if pkg.get("name") and _norm_name(pkg["name"], eco) != want:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges use commit hashes, not versions
            introduced: str | None = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
                    fixes.append(fixed)
                    if (
                        containing is None
                        and dep.version
                        and _in_interval(dep.version, introduced, fixed, eco)
                    ):
                        containing = fixed
                    introduced = None

    if containing:
        return containing
    if not fixes:
        return None
    best = fixes[0]
    for f in fixes[1:]:
        if less_than(best, f, eco):
            best = f
    return best


def _in_interval(
    version: str, introduced: str | None, fixed: str, ecosystem: str
) -> bool:
    """True if ``introduced <= version < fixed`` (``"0"`` means the beginning)."""
    if introduced and introduced != "0" and less_than(version, introduced, ecosystem):
        return False
    return less_than(version, fixed, ecosystem)
