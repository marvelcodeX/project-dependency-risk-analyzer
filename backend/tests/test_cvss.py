"""Tests for the CVSS base-score calculator and OSV severity extraction."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from app.services.cvss import base_score_from_vector, severity_label
from app.services.osv_client import _extract_severity


# Reference vectors + expected base scores from the official CVSS v3.1 spec /
# NVD calculator. These are the canonical check values.
@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # RCE-style
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # info disclosure
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),  # local privesc
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),  # low
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # XSS, scope changed
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # v3.0 also works
    ],
)
def test_base_score_matches_reference(vector, expected):
    assert base_score_from_vector(vector) == expected


def test_bare_numeric_score_passthrough():
    assert base_score_from_vector("7.5") == 7.5


def test_unsupported_vector_returns_none():
    # CVSS v2 and v4 vectors are not scored here.
    assert base_score_from_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert base_score_from_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N") is None
    assert base_score_from_vector("") is None


def test_severity_label_boundaries():
    assert severity_label(9.8) == "CRITICAL"
    assert severity_label(9.0) == "CRITICAL"
    assert severity_label(7.0) == "HIGH"
    assert severity_label(4.0) == "MEDIUM"
    assert severity_label(0.1) == "LOW"
    assert severity_label(0.0) == "NONE"


def test_extract_severity_from_cvss_vector():
    vuln = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
    }
    level, score, vector = _extract_severity(vuln)
    assert level == "CRITICAL"
    assert score == 9.8
    assert vector.startswith("CVSS:3.1")


def test_extract_severity_falls_back_to_database_specific():
    vuln = {"severity": [], "database_specific": {"severity": "moderate"}}
    level, score, vector = _extract_severity(vuln)
    assert level == "MODERATE"
    assert score is None
    assert vector is None


def test_extract_severity_unknown_when_absent():
    assert _extract_severity({}) == ("UNKNOWN", None, None)
