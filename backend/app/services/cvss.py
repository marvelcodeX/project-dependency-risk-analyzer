"""CVSS parsing helpers.

OSV returns severity as a CVSS *vector string* (e.g.
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``), not a bare number, so we
compute the base score from the vector using the official CVSS v3.0/v3.1
formula (https://www.first.org/cvss/v3.1/specification-document).
"""

import math

# Metric weights (CVSS v3.0 / v3.1 are identical for the base metrics we use).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
# Privileges Required depends on Scope (changed vs. unchanged).
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _parse_vector(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" in part:
            key, _, value = part.partition(":")
            metrics[key.upper()] = value.upper()
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 roundup: round up to one decimal place, avoiding FP drift."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score_from_vector(score_or_vector: str) -> float | None:
    """Return the CVSS base score for a v3.x vector string.

    Also tolerates a bare numeric string (some feeds provide the score
    directly). Returns ``None`` for CVSS v2/v4 vectors or anything it can't
    parse — callers fall back to other severity signals.
    """
    if not score_or_vector:
        return None

    # Some sources provide the numeric score directly.
    try:
        return float(score_or_vector)
    except (ValueError, TypeError):
        pass

    if not score_or_vector.upper().startswith("CVSS:3"):
        return None  # v2/v4 vectors use different formulas — not handled here.

    m = _parse_vector(score_or_vector)
    try:
        scope_changed = m["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = pr_table[m["PR"]]
        ui = _UI[m["UI"]]
        conf = _CIA[m["C"]]
        integ = _CIA[m["I"]]
        avail = _CIA[m["A"]]
    except KeyError:
        return None  # missing/unknown base metric

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_label(score: float) -> str:
    """Map a CVSS base score to the standard qualitative severity rating."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"
