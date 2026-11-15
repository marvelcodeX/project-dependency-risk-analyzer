"""Resolve a concrete version for dependencies the manifest leaves unversioned.

``numpy`` or ``urllib3<2`` in a requirements.txt (or ``"*"`` in a package.json)
installs whatever the registry currently offers. Querying OSV *without* a
version returns every advisory ever filed for the package, most of them long
fixed — pure noise. So we ask the registry which version an install would pick
today and scan that, marking it ``version_source="latest"``.

Best-effort by design: if the registry can't be reached or nothing matches,
the dependency is left unversioned and scanned the old (noisy but safe) way.
"""

import asyncio

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from app.schemas.scan import Dependency

PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_LATEST_URL = "https://registry.npmjs.org/{name}/latest"

_MAX_CONCURRENCY = 10
_TIMEOUT = 15.0
_NPM_ANY = {"", "*", "latest", "x", "X"}


async def _fetch_json(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        resp = await client.get(url)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except (httpx.HTTPError, ValueError):
        return None


def needs_resolution(dep: Dependency) -> bool:
    """True for registry packages whose manifest gave no usable version."""
    if dep.version is not None:
        return False
    eco = dep.ecosystem.lower()
    if eco == "pypi":
        return not dep.raw_spec.strip().startswith("@")  # PEP 508 URL ref
    if eco == "npm":
        return dep.raw_spec.strip() in _NPM_ANY  # not file:/git:/ranges
    return False


def pick_pypi_version(data: dict, raw_spec: str) -> str | None:
    """Newest stable, non-yanked release satisfying ``raw_spec`` (e.g. ``<2``)."""
    try:
        spec = SpecifierSet(raw_spec.strip().strip("()"))
    except InvalidSpecifier:
        return None
    best: Version | None = None
    for raw, files in (data.get("releases") or {}).items():
        if not files or all(f.get("yanked") for f in files):
            continue  # no artifacts, or every artifact yanked
        try:
            v = Version(raw)
        except InvalidVersion:
            continue
        if v.is_prerelease or v.is_devrelease or v not in spec:
            continue
        if best is None or v > best:
            best = v
    return str(best) if best else None


async def _resolve_one(client: httpx.AsyncClient, dep: Dependency) -> str | None:
    if dep.ecosystem.lower() == "pypi":
        data = await _fetch_json(client, PYPI_URL.format(name=dep.name))
        return pick_pypi_version(data, dep.raw_spec) if data else None
    data = await _fetch_json(client, NPM_LATEST_URL.format(name=dep.name))
    version = (data or {}).get("version")
    return version if isinstance(version, str) and version[:1].isdigit() else None


async def resolve_unversioned(deps: list[Dependency]) -> None:
    """Fill in ``version`` for unversioned PyPI/npm deps, in place."""
    todo = [d for d in deps if needs_resolution(d)]
    if not todo:
        return
    sem = asyncio.Semaphore(_MAX_CONCURRENCY)
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:

        async def one(dep: Dependency) -> None:
            async with sem:
                version = await _resolve_one(client, dep)
            if version:
                dep.version = version
                dep.version_source = "latest"
                dep.pinned = False

        await asyncio.gather(*(one(d) for d in todo))
