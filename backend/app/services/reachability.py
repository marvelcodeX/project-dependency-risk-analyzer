"""Lightweight reachability analysis via Python AST.

Given a project's source code, work out which vulnerable dependencies are
actually imported — many CVEs live in packages your code never touches, so
this cuts noise. This is an *import-level* check (Phase 3); confirming that the
specific vulnerable function is called is a later refinement.

Classification for a package, given the set of top-level modules imported by
the source:
- REACHABLE               — the package's import name appears in the source.
- UNREACHABLE             — we know its import name and it's NOT imported.
- POTENTIALLY_REACHABLE   — source was analyzed but we aren't confident of the
                            package's import name, so we hedge.
- UNKNOWN                 — no source provided; we can't tell.
"""

import ast

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
    """Return the set of top-level module names imported across .py sources.

    Files that aren't Python or fail to parse are skipped silently.
    """
    modules: set[str] = set()
    for name, content in source_files.items():
        if not name.endswith(".py") and name != "":
            # Allow pasted code under a blank/py name; skip obvious non-python.
            if "." in name:
                continue
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0].lower())
            elif isinstance(node, ast.ImportFrom):
                # Skip relative imports (level > 0) — those are local modules.
                if node.level == 0 and node.module:
                    modules.add(node.module.split(".")[0].lower())
    return modules


def _import_names_for(pkg: str) -> tuple[set[str], bool]:
    """Return (candidate import names, confident?) for a package."""
    norm = normalize(pkg)
    if norm in _IMPORT_NAMES:
        return {n.lower() for n in _IMPORT_NAMES[norm]}, True
    # Best-guess: the normalized name itself. We're not confident about this.
    return {norm}, False


def classify(pkg: str, imported_modules: set[str], has_source: bool) -> str:
    """Classify one package's reachability against the analyzed imports."""
    if not has_source:
        return UNKNOWN
    names, confident = _import_names_for(pkg)
    if names & imported_modules:
        return REACHABLE
    return UNREACHABLE if confident else POTENTIALLY_REACHABLE
