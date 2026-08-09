"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

The KEV catalog lists CVEs that are being actively exploited in the wild. We
download the whole catalog once and cache the set of CVE IDs in memory, since
it's a single ~1MB JSON file that updates at most daily.
"""

import time

import httpx

from app.core.config import settings

# Module-level cache: (cve_id_set, fetched_at_monotonic).
_cache: tuple[set[str], float] | None = None


async def get_kev_cve_ids(force_refresh: bool = False) -> set[str]:
    """Return the set of CVE IDs in the CISA KEV catalog.

    Cached for ``settings.kev_cache_ttl`` seconds. On any network/parse error
    returns an empty set (enrichment is best-effort — a KEV outage must not
    fail a scan) unless a previous good result is still cached.
    """
    global _cache

    if not force_refresh and _cache is not None:
        ids, fetched_at = _cache
        if time.monotonic() - fetched_at < settings.kev_cache_ttl:
            return ids

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(settings.cisa_kev_url)
        resp.raise_for_status()
        data = resp.json()
        ids = {
            item["cveID"]
            for item in data.get("vulnerabilities", [])
            if item.get("cveID")
        }
    except (httpx.HTTPError, ValueError, KeyError):
        # Fall back to the last good cache if we have one; otherwise empty.
        return _cache[0] if _cache is not None else set()

    _cache = (ids, time.monotonic())
    return ids


def _reset_cache_for_tests() -> None:
    global _cache
    _cache = None
