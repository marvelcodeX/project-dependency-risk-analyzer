"""Parser for Go modules (``go.mod``).

Versions in go.mod are exact (minimal version selection), so every
requirement is treated as pinned. ``replace`` directives that point at another
module version are applied; local-path replacements (``=> ../foo``) drop the
version, since the code no longer comes from a published module.
"""

import re

from app.schemas.scan import Dependency

ECOSYSTEM = "Go"

_COMMENT_RE = re.compile(r"//.*$")


def _strip_v(version: str) -> str:
    # OSV's Go ecosystem uses versions without the leading "v".
    return version[1:] if version.startswith("v") else version


def _directives(content: str) -> list[tuple[str, str]]:
    """Yield ``(verb, args)`` for each directive, flattening ``( ... )`` blocks."""
    out: list[tuple[str, str]] = []
    block: str | None = None
    for raw in content.splitlines():
        line = _COMMENT_RE.sub("", raw).strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = None
            else:
                out.append((block, line))
            continue
        verb, _, rest = line.partition(" ")
        rest = rest.strip()
        if rest == "(":
            block = verb
        else:
            out.append((verb, rest))
    return out


def parse_go_mod(content: str) -> list[Dependency]:
    """Parse module requirements from a ``go.mod`` file."""
    requires: dict[str, str] = {}
    replaces: list[tuple[str, str | None, str, str | None]] = []

    for verb, args in _directives(content):
        parts = args.replace('"', "").split()
        if verb == "require" and len(parts) >= 2:
            requires[parts[0]] = parts[1]
        elif verb == "replace" and "=>" in parts:
            i = parts.index("=>")
            old, new = parts[:i], parts[i + 1:]
            if old and new:
                replaces.append(
                    (
                        old[0],
                        old[1] if len(old) > 1 else None,
                        new[0],
                        new[1] if len(new) > 1 else None,
                    )
                )

    deps: list[Dependency] = []
    for path, version in requires.items():
        name, ver = path, version
        for old_path, old_ver, new_path, new_ver in replaces:
            if old_path == path and old_ver in (None, version):
                if new_path.startswith((".", "/")):
                    name, ver = path, None  # local filesystem replacement
                else:
                    name, ver = new_path, new_ver
                break
        deps.append(
            Dependency(
                name=name,
                version=_strip_v(ver) if ver else None,
                ecosystem=ECOSYSTEM,
                pinned=ver is not None,
                raw_spec=version,
            )
        )
    return deps
