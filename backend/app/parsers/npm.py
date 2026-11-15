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
                    direct=True,
                    depth=0,
                )
            )
    return deps


def _looks_like_version(v: object) -> bool:
    return isinstance(v, str) and bool(v) and v[0].isdigit()


_DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
_ROOT_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")


def _resolve(nodes: dict[str, dict], from_path: str, child: str) -> str | None:
    """Find the install path ``child`` resolves to from ``from_path``.

    Mirrors Node's lookup: try ``<from>/node_modules/<child>``, then each
    ancestor's ``node_modules``, up to the project root.
    """
    base = from_path
    while True:
        cand = f"{base}/node_modules/{child}" if base else f"node_modules/{child}"
        if cand in nodes:
            return cand
        if not base:
            return None
        idx = base.rfind("node_modules/")
        base = base[:idx].rstrip("/") if idx > 0 else ""


def _build(nodes: dict[str, dict], edges: dict[str, list[str]],
           direct_paths: set[str] | None) -> list[Dependency]:
    """Collapse install paths into one Dependency per (name, version).

    ``direct_paths`` is None when the lockfile can't say what's direct (v1).
    """
    depth: dict[str, int] = {}
    if direct_paths is not None:
        frontier = sorted(direct_paths)
        for p in frontier:
            depth[p] = 0
        while frontier:  # breadth-first: shortest distance from the project
            nxt = []
            for p in frontier:
                for c in edges.get(p, []):
                    if c not in depth:
                        depth[c] = depth[p] + 1
                        nxt.append(c)
            frontier = nxt

    def key(p: str) -> str:
        return f"{nodes[p]['name']}@{nodes[p]['version']}"

    out: dict[str, Dependency] = {}
    for p, n in nodes.items():
        k = key(p)
        children = {key(c) for c in edges.get(p, [])}
        d = depth.get(p)
        if k not in out:
            out[k] = Dependency(
                name=n["name"], version=n["version"], ecosystem=ECOSYSTEM,
                pinned=True, raw_spec=n["version"],
                direct=None if direct_paths is None else p in direct_paths,
                depth=d, depends_on=sorted(children),
            )
            continue
        dep = out[k]  # same package installed at several paths: merge
        dep.depends_on = sorted(set(dep.depends_on) | children)
        if direct_paths is not None:
            dep.direct = bool(dep.direct) or p in direct_paths
            if d is not None and (dep.depth is None or d < dep.depth):
                dep.depth = d
    return list(out.values())


def parse_package_lock(content: str) -> list[Dependency]:
    """Parse the full resolved tree from a ``package-lock.json`` (v1–v3).

    Includes the dependency graph: ``direct``/``depth`` (v2/v3 only — v1
    doesn't record which packages the project itself declared) and
    ``depends_on`` edges.
    """
    data = _load_json(content)
    packages = data.get("packages")
    if isinstance(packages, dict):
        return _parse_v2(packages)
    return _parse_v1(data.get("dependencies") or {})


def _parse_v2(packages: dict) -> list[Dependency]:
    """lockfileVersion 2/3: a flat map of install paths → metadata."""
    nodes: dict[str, dict] = {}
    roots: list[str] = []  # the project ("") plus any workspace packages
    for path, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        if not path or "node_modules/" not in path:
            roots.append(path)
            continue
        if meta.get("link"):
            continue  # symlink to a workspace package, which is a root
        version = meta.get("version")
        if _looks_like_version(version):
            name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
            nodes[path] = {"name": name, "version": version, "meta": meta}

    edges: dict[str, list[str]] = {}
    for path, n in nodes.items():
        names = {c for f in _DEP_FIELDS for c in (n["meta"].get(f) or {})}
        resolved = (_resolve(nodes, path, c) for c in sorted(names))
        edges[path] = [r for r in resolved if r and r != path]

    direct: set[str] = set()
    for root in roots:
        meta = packages.get(root) or {}
        for c in {c for f in _ROOT_FIELDS for c in (meta.get(f) or {})}:
            if r := _resolve(nodes, root, c):
                direct.add(r)
    return _build(nodes, edges, direct)


def _parse_v1(tree: dict) -> list[Dependency]:
    """lockfileVersion 1: a nested tree with "requires" edges."""
    nodes: dict[str, dict] = {}

    def walk(subtree: dict, prefix: str) -> None:
        for name, meta in subtree.items():
            if not isinstance(meta, dict):
                continue
            path = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
            if _looks_like_version(meta.get("version")):
                nodes[path] = {"name": name, "version": meta["version"], "meta": meta}
            if isinstance(meta.get("dependencies"), dict):
                walk(meta["dependencies"], path)

    walk(tree, "")
    edges: dict[str, list[str]] = {}
    for path, n in nodes.items():
        requires = n["meta"].get("requires") or {}
        resolved = (_resolve(nodes, path, c) for c in sorted(requires))
        edges[path] = [r for r in resolved if r and r != path]
    return _build(nodes, edges, None)
