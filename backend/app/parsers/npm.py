"""Parsers for npm manifests: ``package.json`` and ``package-lock.json``.

``package.json`` holds semver *ranges* (``^1.2.3``), so versions are a
best-guess lower bound. ``package-lock.json`` holds the exact resolved tree
(including transitive deps), so prefer it when both are available.
"""

import json
import re

from app.parsers.errors import ManifestError
from app.schemas.scan import Dependency

ECOSYSTEM = "npm"

# Dependency sections of package.json that end up installed.
_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")

# Specs that don't point at a registry version we can look up.
_NON_REGISTRY_PREFIXES = (
    "file:", "link:", "workspace:", "portal:", "git", "http:", "https:",
    "github:", "gitlab:", "bitbucket:",
)

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(-[0-9A-Za-z.-]+)?")
_EXACT_RE = re.compile(r"^=?v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def _load_json(content: str) -> dict:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"Invalid JSON: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(data, dict):
        raise ManifestError("Expected a JSON object at the top level")
    return data


def _version_from_range(spec: str) -> tuple[str | None, bool]:
    """Return ``(version, pinned)`` for an npm semver range.

    Exact versions are pinned. Ranges (``^``, ``~``, ``>=``, ``1.x``,
    ``1.0.0 - 2.0.0``) use their lower bound; for ``a || b`` the first
    alternative is used. Upper-bound-only or wildcard specs yield ``None``.
    """
    spec = spec.strip()
    if _EXACT_RE.match(spec):
        return spec.lstrip("=v"), True

    first = spec.split("||", 1)[0].strip()
    if not first or first in ("*", "latest", "x", "X") or first.startswith("<"):
        return None, False

    m = _VERSION_RE.search(first)
    if not m:
        return None, False
    major = m.group(1)
    minor = m.group(2) if m.group(2) and m.group(2).isdigit() else "0"
    patch = m.group(3) if m.group(3) and m.group(3).isdigit() else "0"
    return f"{major}.{minor}.{patch}{m.group(4) or ''}", False


def parse_package_json(content: str) -> list[Dependency]:
    """Parse direct dependencies from a ``package.json``."""
    data = _load_json(content)
    deps: list[Dependency] = []
    seen: set[str] = set()

    for section in _SECTIONS:
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if name in seen or not isinstance(spec, str):
                continue
            seen.add(name)
            if spec.startswith("npm:"):
                # Alias: "foo": "npm:bar@^1.0.0" installs bar.
                target = spec[4:]
                at = target.rfind("@")
                if at > 0:
                    name, spec = target[:at], target[at + 1:]
                else:
                    name, spec = target, ""
            if spec.startswith(_NON_REGISTRY_PREFIXES) or "/" in spec:
                version, pinned = None, False
            else:
                version, pinned = _version_from_range(spec)
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=ECOSYSTEM,
                    pinned=pinned,
                    raw_spec=spec,
                )
            )
    return deps


def _looks_like_version(v: object) -> bool:
    return isinstance(v, str) and bool(v) and v[0].isdigit()


def parse_package_lock(content: str) -> list[Dependency]:
    """Parse the full resolved tree from a ``package-lock.json`` (v1–v3)."""
    data = _load_json(content)
    found: dict[tuple[str, str], Dependency] = {}

    def _add(name: str, version: str) -> None:
        key = (name, version)
        if key not in found:
            found[key] = Dependency(
                name=name,
                version=version,
                ecosystem=ECOSYSTEM,
                pinned=True,
                raw_spec=version,
            )

    packages = data.get("packages")
    if isinstance(packages, dict):
        # lockfileVersion 2/3: flat map of install paths.
        for path, meta in packages.items():
            if not path or "node_modules/" not in path or not isinstance(meta, dict):
                continue  # "" is the root project; others are workspaces
            if meta.get("link"):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
            version = meta.get("version")
            if _looks_like_version(version):
                _add(name, version)
    else:
        # lockfileVersion 1: nested "dependencies" tree.
        def _walk(tree: dict) -> None:
            for name, meta in tree.items():
                if not isinstance(meta, dict):
                    continue
                version = meta.get("version")
                if _looks_like_version(version):
                    _add(name, version)
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    _walk(nested)

        _walk(data.get("dependencies") or {})

    return list(found.values())
