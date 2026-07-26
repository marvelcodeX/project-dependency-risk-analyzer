"""Parser for Python requirements.txt files.

Handles formats like:
    flask==2.0.1
    requests>=2.25.0,<3.0.0
    numpy
    # comments and blank lines
    -r other-requirements.txt  (ignored)
"""

import re
from app.schemas.scan import Dependency

# Matches: package_name, optional extras, optional version specifiers
_LINE_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"(\[[^\]]*\])?"                                    # optional extras [dev,test]
    r"(.*)?$"                                           # version specifiers
)

_SKIP_PREFIXES = ("-r ", "-c ", "-e ", "--", "#")


def parse_requirements_txt(content: str) -> list[Dependency]:
    """Parse a requirements.txt string into a list of Dependency objects."""
    dependencies: list[Dependency] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or any(line.startswith(p) for p in _SKIP_PREFIXES):
            continue

        # Strip inline comments
        line = line.split("#")[0].strip()
        if not line:
            continue

        match = _LINE_RE.match(line)
        if not match:
            continue

        name = match.group(1).lower()
        version_spec = (match.group(4) or "").strip()

        # Extract pinned version (==X.Y.Z)
        version: str | None = None
        pinned = False

        if version_spec.startswith("=="):
            version = version_spec[2:].strip()
            pinned = True
        elif version_spec:
            # For ranges like >=2.0,<3.0, extract the lower bound as a best guess
            lower = re.search(r">=?\s*([0-9][0-9a-zA-Z.*]*)", version_spec)
            if lower:
                version = lower.group(1)
        # If no version at all, version stays None

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
