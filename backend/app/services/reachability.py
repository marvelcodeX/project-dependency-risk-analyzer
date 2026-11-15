"""Lightweight reachability analysis: Python (AST) and JavaScript/TypeScript.

Given a project's source code, work out which vulnerable dependencies are
actually imported — many CVEs live in packages your code never touches, so
this cuts noise. This is an *import-level* check (Phase 3); confirming that the
specific vulnerable function is called is a later refinement.

When the manifest provides a dependency graph (npm lockfiles), transitive
packages inherit reachability from the packages that pull them in: a package
reached through an imported dependency is POTENTIALLY_REACHABLE, and one with
no path from any imported package is UNREACHABLE.

Classification for a package, given the set of top-level modules imported by
the source:
- REACHABLE               — the package's import name appears in the source.
- UNREACHABLE             — we know its import name and it's NOT imported.
- POTENTIALLY_REACHABLE   — source was analyzed but we aren't confident of the
                            package's import name, so we hedge.
- UNKNOWN                 — no source provided; we can't tell.
"""

import ast
import re

from app.schemas.scan import Dependency

# Reachability states.
REACHABLE = "REACHABLE"
UNREACHABLE = "UNREACHABLE"
POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE"
UNKNOWN = "UNKNOWN"

# PyPI distribution name (normalized) → top-level import module name(s).
# Only the cases where the import name differs from the package name, or where
# we want a confident mapping, need to live here.
_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "beautifulsoup4": ("bs4",),
    "pillow": ("pil",),
    "scikit_learn": ("sklearn",),
    "scikit_image": ("skimage",),
    "python_dateutil": ("dateutil",),
    "opencv_python": ("cv2",),
    "protobuf": ("google",),
    "pyjwt": ("jwt",),
    "python_jose": ("jose",),
    "mysqlclient": ("mysqldb",),
    "psycopg2_binary": ("psycopg2",),
    "typing_extensions": ("typing_extensions",),
    "setuptools": ("setuptools", "pkg_resources"),
    "attrs": ("attr", "attrs"),
    # Common packages whose import name equals the distribution name — listed
    # so they count as "confident" (enabling a definitive UNREACHABLE verdict).
    "flask": ("flask",),
    "django": ("django",),
    "requests": ("requests",),
    "numpy": ("numpy",),
    "jinja2": ("jinja2",),
    "werkzeug": ("werkzeug",),
    "sqlalchemy": ("sqlalchemy",),
    "urllib3": ("urllib3",),
    "cryptography": ("cryptography",),
    "lxml": ("lxml",),
    "click": ("click",),
    "markupsafe": ("markupsafe",),
    "certifi": ("certifi",),
    "idna": ("idna",),
    "boto3": ("boto3",),
    "fastapi": ("fastapi",),
    "pydantic": ("pydantic",),
    "httpx": ("httpx",),
    "starlette": ("starlette",),
}


def normalize(pkg: str) -> str:
    """Normalize a PyPI name for lookup (PEP 503-ish: lowercase, - . → _)."""
    return pkg.strip().lower().replace("-", "_").replace(".", "_")


def analyze_imports(source_files: dict[str, str]) -> set[str]:
    """Top-level modules imported across the Python sources (see analyze_sources)."""
    return analyze_sources(source_files).get(PYTHON, set())


# ---- language routing --------------------------------------------------------

_PY_EXT = (".py", ".pyi")
_JS_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte")

# Source languages → the ecosystem whose packages they import.
PYTHON, JAVASCRIPT = "PyPI", "npm"


def _language(name: str) -> str | None:
    """PYTHON / JAVASCRIPT by extension; "" for extensionless (pasted) code."""
    lower = name.lower()
    if lower.endswith(".d.ts"):
        return None  # type declarations: no runtime imports
    if lower.endswith(_PY_EXT):
        return PYTHON
    if lower.endswith(_JS_EXT):
        return JAVASCRIPT
    base = lower.rsplit("/", 1)[-1]
    return "" if "." not in base else None


def is_source_file(name: str) -> bool:
    """True for files the analyzer reads (Python or JS/TS, not .d.ts)."""
    return bool(_language(name))


def _python_imports(content: str) -> set[str] | None:
    """Top-level modules imported by Python code, or None if it doesn't parse."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return None
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0].lower())
        elif isinstance(node, ast.ImportFrom):
            # Skip relative imports (level > 0) — those are local modules.
            if node.level == 0 and node.module:
                modules.add(node.module.split(".")[0].lower())
    return modules


# ---- JavaScript / TypeScript --------------------------------------------------

_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_JS_LINE_COMMENT = re.compile(r"(^|[^:\\])//[^\n]*")  # keep "http://" in strings
_JS_PATTERNS = [
    # import x from "y" · import {a, b} from "y" · import * as x from "y" · import "y"
    re.compile(r"\bimport\s+(type\s+)?(?:[\w*${}\s,]+?\s+from\s+)?[\"']([^\"']+)[\"']"),
    # export {a} from "y" · export * from "y"
    re.compile(r"\bexport\s+(type\s+)?(?:\*(?:\s+as\s+\w+)?|\{[^}]*\})\s*from\s+[\"']([^\"']+)[\"']"),
    # require("y") · import("y")
    re.compile(r"\b(?:require|import)\s*\(\s*()[\"']([^\"']+)[\"']\s*\)"),
]
_NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net", "os",
    "path", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
}


def js_package_name(specifier: str) -> str | None:
    """npm package a module specifier refers to, or None for local/builtin ones.

    ``lodash/fp`` → ``lodash``; ``@scope/pkg/sub`` → ``@scope/pkg``;
    ``./x``, ``/abs``, ``node:fs``, ``fs``, ``@/alias``, ``~/alias`` → None.
    """
    spec = specifier.strip()
    if not spec or spec.startswith((".", "/", "node:", "~", "#")) or ":" in spec:
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        if len(parts) < 2 or parts[0] == "@" or not parts[1]:
            return None  # "@/components" is a bundler path alias
        name = f"{parts[0]}/{parts[1]}"
    else:
        name = parts[0]
    if name in _NODE_BUILTINS:
        return None
    return name.lower()


def _js_imports(content: str) -> set[str]:
    """npm packages imported at runtime by JS/TS code (type-only imports skipped)."""
    code = _JS_BLOCK_COMMENT.sub(" ", content)
    code = _JS_LINE_COMMENT.sub(r"\1", code)
    found: set[str] = set()
    for pattern in _JS_PATTERNS:
        for type_only, spec in pattern.findall(code):
            if type_only:
                continue  # erased by the TypeScript compiler
            if name := js_package_name(spec):
                found.add(name)
    return found


def analyze_sources(source_files: dict[str, str]) -> dict[str, set[str]]:
    """Imported packages per ecosystem, only for languages actually present.

    Returns e.g. ``{"PyPI": {"flask"}, "npm": {"lodash"}}``. A language with no
    analyzable file is absent — its packages stay UNKNOWN rather than being
    wrongly called UNREACHABLE. Extensionless (pasted) code is tried as Python
    first, then as JavaScript.
    """
    result: dict[str, set[str]] = {}
    for name, content in source_files.items():
        lang = _language(name)
        if lang is None:
            continue
        if lang in (PYTHON, ""):
            py = _python_imports(content)
            if py is not None:
                result.setdefault(PYTHON, set()).update(py)
                continue
            if lang == PYTHON:
                continue  # a .py file that doesn't parse
        result.setdefault(JAVASCRIPT, set()).update(_js_imports(content))
    return result


def _import_names_for(pkg: str) -> tuple[set[str], bool]:
    """Return (candidate import names, confident?) for a package."""
    norm = normalize(pkg)
    if norm in _IMPORT_NAMES:
        return {n.lower() for n in _IMPORT_NAMES[norm]}, True
    # Best-guess: the normalized name itself. We're not confident about this.
    return {norm}, False


def classify(
    pkg: str,
    imported_modules: set[str],
    has_source: bool,
    ecosystem: str = "PyPI",
) -> str:
    """Classify one package against the imports of its own ecosystem's code.

    Python (PyPI) and JavaScript (npm) are analyzed; other ecosystems are
    always UNKNOWN.
    """
    eco = ecosystem.lower()
    if not has_source or eco not in ("pypi", "npm"):
        return UNKNOWN
    if eco == "npm":
        name = pkg.lower()
        # npm import names equal package names, so "not imported" is certain.
        # @types/* packages are type declarations with no runtime code.
        return REACHABLE if name in imported_modules else UNREACHABLE
    names, confident = _import_names_for(pkg)
    if names & imported_modules:
        return REACHABLE
    return UNREACHABLE if confident else POTENTIALLY_REACHABLE


def classify_all(
    deps: list[Dependency], imports: dict[str, set[str]]
) -> dict[str, str]:
    """Reachability for every dependency of one manifest, keyed by ``dep.key``.

    Starts from each package's own import status, then propagates through the
    dependency graph (``depends_on``) when the manifest has one:

    - imported by the code → REACHABLE
    - pulled in (transitively) by a REACHABLE package → POTENTIALLY_REACHABLE
      (its code runs, but we can't tell whether the vulnerable part does)
    - otherwise the import-level verdict stands (UNREACHABLE when certain).

    Transitive packages with no graph to check are never called UNREACHABLE:
    something the project uses may depend on them.
    """
    result: dict[str, str] = {}
    for d in deps:
        eco = PYTHON if d.ecosystem.lower() == "pypi" else d.ecosystem
        analyzed = eco in imports
        result[d.key] = classify(d.name, imports.get(eco, set()), analyzed, d.ecosystem)

    has_graph = any(d.depends_on for d in deps)
    if has_graph:
        children = {d.key: d.depends_on for d in deps}
        frontier = [k for k, r in result.items() if r == REACHABLE]
        seen = set(frontier)
        while frontier:
            nxt = []
            for k in frontier:
                for c in children.get(k, []):
                    if c in seen or c not in result:
                        continue
                    seen.add(c)
                    if result[c] in (UNREACHABLE, POTENTIALLY_REACHABLE):
                        result[c] = POTENTIALLY_REACHABLE
                    nxt.append(c)
            frontier = nxt
    else:
        for d in deps:
            if d.direct is False and result[d.key] == UNREACHABLE:
                result[d.key] = POTENTIALLY_REACHABLE
    return result
