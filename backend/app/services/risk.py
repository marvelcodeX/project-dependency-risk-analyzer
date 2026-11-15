"""Composite risk-scoring engine.

Goes beyond raw CVSS to a 0-100 score, following the model in the project plan
(section 9.2).

Components (max shown):
- base          (40): CVSS base score, normalized. Falls back to a coarse
                      mapping from the qualitative severity label when no CVSS.
- exploit       (25): +25 if the CVE is in the CISA KEV catalog (in the wild),
                      else +20 if a public exploit / PoC is referenced.
- reachability  (20): does the project's code actually import the package?
                      REACHABLE +20, POTENTIALLY/UNKNOWN +10, UNREACHABLE +0.
- fix           (10): +10 when NO patched version exists (harder to remediate).
- depth          (5): plan §9.2 — direct +5, transitive within 2 hops +3,
                      deeper +1 (transitive of unknown depth +3). When the
                      manifest can't say what's direct (requirements.txt, npm
                      lockfile v1), falls back to version exposure: a non-exact
                      version +5, an exact pin +3.
"""

from app.schemas.scan import Dependency, Vulnerability
from app.services import reachability as reach

# Fallback base contribution (out of 40) when a numeric CVSS is unavailable.
_SEVERITY_BASE = {
    "CRITICAL": 38.0,
    "HIGH": 30.0,
    "MEDIUM": 20.0,
    "MODERATE": 20.0,
    "LOW": 8.0,
}

# Reachability contribution (out of 20). UNKNOWN (no source analyzed) and
# POTENTIALLY_REACHABLE both get the neutral middle value; a confirmed
# UNREACHABLE finding is deprioritized to 0.
_REACH_POINTS = {
    reach.REACHABLE: 20.0,
    reach.POTENTIALLY_REACHABLE: 10.0,
    reach.UNKNOWN: 10.0,
    reach.UNREACHABLE: 0.0,
}


def _base_component(vuln: Vulnerability) -> float:
    if vuln.cvss_score is not None:
        return (vuln.cvss_score / 10.0) * 40.0
    return _SEVERITY_BASE.get(vuln.severity.upper(), 0.0)


def risk_level(score: int) -> str:
    """Bucket a composite risk score into a qualitative level."""
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _depth_points(dep: Dependency) -> float:
    if dep.direct is True:
        return 5.0
    if dep.direct is False:
        return 1.0 if (dep.depth is not None and dep.depth > 2) else 3.0
    # Unknown graph position: a floating version can resolve to anything.
    return 3.0 if dep.pinned else 5.0


def compute_risk(
    vuln: Vulnerability,
    dep: Dependency,
    in_kev: bool,
    reachability: str = reach.UNKNOWN,
) -> tuple[int, str]:
    """Return ``(risk_score, risk_level)`` for a vulnerability in context."""
    base = _base_component(vuln)
    if in_kev:
        exploit = 25.0
    elif vuln.has_public_exploit:
        exploit = 20.0
    else:
        exploit = 0.0
    reach_pts = _REACH_POINTS.get(reachability, 10.0)
    fix = 0.0 if vuln.fixed_version else 10.0
    depth = _depth_points(dep)

    score = int(round(min(base + exploit + reach_pts + fix + depth, 100.0)))
    return score, risk_level(score)
