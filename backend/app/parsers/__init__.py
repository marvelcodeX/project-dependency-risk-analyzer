"""Dependency manifest parsers, one per ecosystem.

``parse_manifest`` picks a parser from the filename, falling back to sniffing
the content (pasted text often arrives with a generic filename).
"""

import os
from collections.abc import Callable

from app.parsers.errors import ManifestError
from app.parsers.go_mod import parse_go_mod
from app.parsers.maven import parse_pom_xml
from app.parsers.npm import parse_package_json, parse_package_lock
from app.parsers.requirements import parse_requirements_txt
from app.schemas.scan import Dependency

__all__ = ["ManifestError", "SUPPORTED_FORMATS", "detect_format", "parse_manifest"]

Parser = Callable[[str], list[Dependency]]

# Format id → parser. Ids double as the canonical filename for each format.
_PARSERS: dict[str, Parser] = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "go.mod": parse_go_mod,
    "pom.xml": parse_pom_xml,
}

SUPPORTED_FORMATS = tuple(_PARSERS)


def detect_format(filename: str, content: str) -> str:
    """Return the format id for a manifest, by name first, then by content."""
    base = os.path.basename(filename or "").lower()
    if base in _PARSERS:
        return base
    # Common variants: requirements-dev.txt, requirements/base.txt, *.pom ...
    if base.endswith(".txt") and "requirements" in base:
        return "requirements.txt"
    if base.endswith(".pom"):
        return "pom.xml"
    if base == "npm-shrinkwrap.json":
        return "package-lock.json"

    head = content.lstrip()[:2000]
    if head.startswith("{"):
        return "package-lock.json" if '"lockfileVersion"' in head else "package.json"
    if head.startswith("<") and "<project" in head:
        return "pom.xml"
    if head.startswith("module ") or "\nmodule " in head:
        return "go.mod"
    if base.endswith(".txt") or not base or base in ("pasted", "-"):
        return "requirements.txt"
    raise ManifestError(
        f"Unsupported manifest '{filename}'. Supported: {', '.join(SUPPORTED_FORMATS)}"
    )


def parse_manifest(content: str, filename: str) -> list[Dependency]:
    """Parse any supported manifest. Raises ``ManifestError`` if unsupported."""
    return _PARSERS[detect_format(filename, content)](content)
