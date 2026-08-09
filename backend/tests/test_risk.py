"""Tests for the composite risk-scoring engine."""

from app.schemas.scan import Dependency, Vulnerability
from app.services import reachability as reach
from app.services.risk import compute_risk, risk_level


def _vuln(**kw) -> Vulnerability:
    base = dict(id="OSV-1", summary="x")
    base.update(kw)
    return Vulnerability(**base)


def test_risk_level_buckets():
    assert risk_level(75) == "CRITICAL"
    assert risk_level(70) == "CRITICAL"
    assert risk_level(40) == "HIGH"
    assert risk_level(20) == "MEDIUM"
    assert risk_level(1) == "LOW"
    assert risk_level(0) == "NONE"


def test_kev_and_no_fix_push_score_up():
    dep = Dependency(name="flask", version="2.0.1", pinned=True)
    v = _vuln(cvss_score=9.8, fixed_version=None)
    score, level = compute_risk(v, dep, in_kev=True)
    # base 39.2 + exploit 25 + reach 10 (unknown) + no-fix 10 + exposure 3 = 87.2
    assert score == 87
    assert level == "CRITICAL"


def test_fix_available_and_not_kev():
    dep = Dependency(name="flask", version="2.0.1", pinned=True)
    v = _vuln(cvss_score=7.5, fixed_version="2.3.2")
    score, level = compute_risk(v, dep, in_kev=False)
    # base 30 + 0 + reach 10 + 0 + exposure 3 = 43
    assert score == 43
    assert level == "HIGH"


def test_unpinned_adds_exposure():
    dep = Dependency(name="numpy", version="1.0", pinned=False)
    v = _vuln(cvss_score=5.0, fixed_version="2.0")
    score, _ = compute_risk(v, dep, in_kev=False)
    # base 20 + 0 + reach 10 + 0 + exposure 5 = 35
    assert score == 35


def test_falls_back_to_severity_without_cvss():
    dep = Dependency(name="pkg", version="1.0", pinned=True)
    v = _vuln(cvss_score=None, severity="HIGH", fixed_version="1.1")
    score, _ = compute_risk(v, dep, in_kev=False)
    # base 30 (HIGH fallback) + 0 + reach 10 + 0 + 3 = 43
    assert score == 43


def test_reachable_scores_higher_than_unreachable():
    dep = Dependency(name="flask", version="2.0.1", pinned=True)
    v = _vuln(cvss_score=7.5, fixed_version="2.3.2")
    reachable, _ = compute_risk(v, dep, False, reach.REACHABLE)
    unreachable, _ = compute_risk(v, dep, False, reach.UNREACHABLE)
    assert reachable - unreachable == 20  # full reachability weight
    # UNREACHABLE deprioritizes below the UNKNOWN baseline.
    unknown, _ = compute_risk(v, dep, False, reach.UNKNOWN)
    assert unknown - unreachable == 10


def test_score_capped_at_100():
    dep = Dependency(name="pkg", version="1.0", pinned=False)
    v = _vuln(cvss_score=10.0, fixed_version=None)
    # 40 + 25 + 20 (reachable) + 10 + 5 = 100
    score, level = compute_risk(v, dep, in_kev=True, reachability=reach.REACHABLE)
    assert score == 100
    assert level == "CRITICAL"
