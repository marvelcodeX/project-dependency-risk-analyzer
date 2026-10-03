"""Parser for Python requirements.txt files.

Handles formats like:
    flask==2.0.1
    requests>=2.25.0,<3.0.0
    django~=4.2
    numpy
    uvicorn[standard]==0.34.0
    pywin32==306 ; sys_platform == "win32"     (environment markers)
    flask==2.0.1 \\
        --hash=sha256:...                      (hash-pinned, continued lines)
    mypkg @ https://example.com/mypkg.zip      (direct URL — no version)
    # comments and blank lines
    -r other-requirements.txt                  (options are ignored)
"""

import re
from app.schemas.scan import Dependency

# Matches: package_name, optional extras, then the rest (specifiers / URL)
_LINE_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"\s*(\[[^\]]*\])?"                                 # optional extras [dev,test]
    r"(.*)?$"                                           # version specifiers
)

# Per-requirement options that can trail a spec (pip "hash-checking mode").
_TRAILING_OPTION_RE = re.compile(r"\s--?[A-Za-z][\w-]*(=\S*|\s+\S+)?")

# pip treats "#" as a comment only at line start or after whitespace, so URL
# fragments like ``#egg=foo`` survive.
_COMMENT_RE = re.compile(r"(^|\s)#.*$")

_VERSION = r"([0-9][0-9a-zA-Z.*+!_-]*)"


def _logical_lines(content: str) -> list[str]:
    """Join backslash-continued lines, as pip does."""
    lines: list[str] = []
    buf = ""
    for raw in content.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        lines.append(buf + raw)
        buf = ""
    if buf:
        lines.append(buf)
    return lines


def _version_from_spec(spec: str) -> tuple[str | None, bool]:
    """Return ``(version, pinned)`` from a specifier set like ``>=1.0,<2``.

    An exact ``==``/``===`` pin wins. Otherwise the lower bound (``>=``, ``>``,
    ``~=``) is used as a best guess of the installed version. Upper-bound-only
    specs yield ``None`` — the installed version is genuinely unknown.
    """
    exact = re.search(r"===?\s*" + _VERSION, spec)
    if exact:
        version = exact.group(1)
        if "*" in version:
            # ``==2.*`` is a prefix match, not a pin: use the floor.
            return version.replace(".*", "").rstrip(".") or None, False
        return version, True
    lower = re.search(r"(?:>=?|~=)\s*" + _VERSION, spec)
    if lower:
        return lower.group(1), False
    return None, False


def parse_requirements_txt(content: str) -> list[Dependency]:
    """Parse a requirements.txt string into a list of Dependency objects."""
    dependencies: list[Dependency] = []

    for raw_line in _logical_lines(content):
        line = _COMMENT_RE.sub("", raw_line).strip()

        # Blank lines and pip options (-r, -c, -e, --index-url, ...).
        if not line or line.startswith("-"):
            continue

        # Drop environment markers ("; python_version < '3.8'"). A direct URL
        # can contain ";" only after "@", which has no version info anyway.
        line = line.split(";", 1)[0].strip()
        # Drop trailing per-requirement options such as --hash=sha256:...
        line = _TRAILING_OPTION_RE.sub("", " " + line).strip()

        match = _LINE_RE.match(line)
        if not match:
            continue

        name = match.group(1).lower()
        version_spec = (match.group(4) or "").strip()

        if version_spec.startswith("@"):
            # PEP 508 direct reference: no version to look up.
            version, pinned = None, False
        else:
            version, pinned = _version_from_spec(version_spec)

        dependencies.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="PyPI",
                pinned=pinned,
                raw_spec=version_spec,
            )
        )

    return dependencies
