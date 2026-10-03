"""Version ordering helpers, used to match a dependency to OSV affected ranges.

PyPI versions are compared with ``packaging`` (PEP 440). Other ecosystems
(npm/Go semver, Maven) use a tolerant generic key: dotted numeric release
segments first, with any pre-release suffix sorting *before* the release.
"""

import re

from packaging.version import InvalidVersion, Version

_SPLIT_RE = re.compile(r"[.\-+_]")


def _generic_key(version: str) -> tuple:
    """Sort key for non-PEP 440 versions (``v1.2.3``, ``1.2.3-beta.1``, ...)."""
    v = version.strip().lstrip("vV")
    # Drop build metadata (semver: ignored for precedence).
    v = v.split("+", 1)[0]
    release, _, pre = v.partition("-")
    nums: list[int] = []
    for part in release.split("."):
        m = re.match(r"\d+", part)
        nums.append(int(m.group()) if m else 0)
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()  # 1.2.0 == 1.2
    # A release (no suffix) sorts after any pre-release of the same version.
    pre_key: tuple = (1,) if not pre else (0,) + tuple(
        (0, int(p), "") if p.isdigit() else (1, 0, p.lower())
        for p in _SPLIT_RE.split(pre)
        if p
    )
    return (tuple(nums), pre_key)


def sort_key(version: str, ecosystem: str) -> tuple:
    """Return a comparable key for ``version`` in ``ecosystem``."""
    if ecosystem.lower() == "pypi":
        try:
            return (0, Version(version))
        except InvalidVersion:
            pass
    return (1, _generic_key(version))


def less_than(a: str, b: str, ecosystem: str) -> bool:
    """True if version ``a`` sorts strictly before ``b``.

    Falls back to the generic key for both sides if one isn't PEP 440-valid,
    so the comparison never mixes key kinds.
    """
    ka, kb = sort_key(a, ecosystem), sort_key(b, ecosystem)
    if ka[0] != kb[0]:
        ka, kb = (1, _generic_key(a)), (1, _generic_key(b))
    return ka < kb
