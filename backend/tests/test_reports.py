"""Tests for report export (renderers + /api/scans/{id}/report)."""

import json
from datetime import datetime, timezone

import httpx
import pytest

import app.services.scanner as scanner_mod
from app.core.db import init_db
from app.main import app
from app.reports import ReportFormat, render_report
from app.reports.common import purl
from app.reports.cyclonedx import render_cyclonedx
from app.reports.html_report import render_html
from app.reports.markdown import render_markdown
from app.reports.sarif import render_sarif
from app.schemas.scan import (
    Dependency,
    DependencyScanResult,
    ScanResponse,
    Vulnerability,
)

EVIL = '<script>alert(1)</script> | pipe'


def _scan() -> ScanResponse:
    flask = Dependency(name="flask", version="2.0.1", pinned=True)
    lodash_old = Dependency(name="lodash", version="3.10.1", ecosystem="npm", pinned=True)
    lodash_new = Dependency(name="lodash", version="4.17.20", ecosystem="npm", pinned=True)
    numpy = Dependency(name="numpy")
    proto = Vulnerability(
        id="GHSA-proto",
        summary="Prototype pollution.",
        aliases=["CVE-2020-8203"],
        severity="HIGH",
        cvss_score=7.4,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
        fixed_version="4.17.21",
        references=["https://example.com/advisory"],
        in_cisa_kev=True,
        risk_score=82,
        risk_level="CRITICAL",
        reachability="UNKNOWN",
    )
    return ScanResponse(
        id=7,
        filename="package-lock.json",
        created_at=datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc),
        total_dependencies=4,
        vulnerable_dependencies=3,
        risk_score=82,
        risk_level="CRITICAL",
        results=[
            DependencyScanResult(
                dependency=flask,
                vulnerabilities=[
                    Vulnerability(
                        id="GHSA-flask",
                        summary=EVIL,
                        details="line1\nline2",
                        severity="MODERATE",
                        risk_score=35,
                        risk_level="MEDIUM",
                        reachability="REACHABLE",
                    )
                ],
            ),
            DependencyScanResult(dependency=lodash_old, vulnerabilities=[proto]),
            DependencyScanResult(dependency=lodash_new, vulnerabilities=[proto]),
            DependencyScanResult(dependency=numpy, vulnerabilities=[]),
        ],
    )


# ---- purl ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("dep", "expected"),
    [
        (Dependency(name="Django_Extensions", version="3.2"), "pkg:pypi/django-extensions@3.2"),
        (Dependency(name="@babel/core", version="7.23.0", ecosystem="npm"), "pkg:npm/%40babel/core@7.23.0"),
        (Dependency(name="github.com/gin-gonic/gin", version="1.9.0", ecosystem="Go"), "pkg:golang/github.com/gin-gonic/gin@v1.9.0"),
        (Dependency(name="org.apache.logging.log4j:log4j-core", version="2.14.1", ecosystem="Maven"), "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
        (Dependency(name="numpy"), "pkg:pypi/numpy"),
        (Dependency(name="x", version="1", ecosystem="Hex"), None),
    ],
)
def test_purl(dep, expected):
    assert purl(dep) == expected


# ---- SARIF -----------------------------------------------------------------


def test_sarif_structure():
    sarif = render_sarif(_scan())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"GHSA-proto", "GHSA-flask"}  # one rule per advisory
    assert rules["GHSA-proto"]["properties"]["security-severity"] == "7.4"
    assert rules["GHSA-flask"]["properties"]["security-severity"] == "5.5"  # fallback

    results = run["results"]
    assert len(results) == 3  # one per (dependency, advisory)
    assert results[0]["ruleId"] == "GHSA-proto"  # highest risk first
    assert results[0]["level"] == "error"
    assert "Upgrade to 4.17.21" in results[0]["message"]["text"]
    assert "CISA KEV" in results[0]["message"]["text"]
    flask = next(r for r in results if r["ruleId"] == "GHSA-flask")
    assert flask["level"] == "warning"
    loc = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uri"] == "package-lock.json"
    # Same advisory on two versions → distinct fingerprints.
    fps = {r["partialFingerprints"]["soteriaFinding/v1"] for r in results}
    assert len(fps) == 3


# ---- CycloneDX -------------------------------------------------------------


def test_cyclonedx_components_and_vulns():
    bom = render_cyclonedx(_scan())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["timestamp"] == "2026-10-01T12:00:00Z"

    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs)) == 4
    assert "pkg:npm/lodash@3.10.1" in refs and "pkg:npm/lodash@4.17.20" in refs
    numpy = next(c for c in bom["components"] if c["name"] == "numpy")
    assert "version" not in numpy

    vulns = {v["id"]: v for v in bom["vulnerabilities"]}
    proto = vulns["GHSA-proto"]
    assert [a["ref"] for a in proto["affects"]] == [
        "pkg:npm/lodash@3.10.1",
        "pkg:npm/lodash@4.17.20",
    ]
    assert proto["ratings"][0] == {
        "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/GHSA-proto"},
        "severity": "high",
        "score": 7.4,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "method": "CVSSv31",
    }
    assert proto["references"][0]["id"] == "CVE-2020-8203"
    assert proto["recommendation"] == "Upgrade to 4.17.21 or later."
    props = {p["name"]: p["value"] for p in proto["properties"]}
    assert props["soteria:cisa_kev"] == "true"
    assert vulns["GHSA-flask"]["ratings"][0]["severity"] == "medium"  # MODERATE
    # Every affects ref must point at a declared component.
    for v in bom["vulnerabilities"]:
        assert all(a["ref"] in refs for a in v["affects"])


# ---- Markdown / HTML -------------------------------------------------------


def test_markdown_escapes_untrusted_text():
    md = render_markdown(_scan())
    assert "Project risk: 82/100 (CRITICAL)" in md
    assert "<script>" not in md
    assert "&lt;script&gt;" in md
    assert "\\| pipe" in md  # pipe can't break the table
    assert "1 finding(s) are actively exploited" not in md  # counts findings
    assert "2 finding(s) are actively exploited" in md
    rows = [l for l in md.splitlines() if l.startswith("| 82")]
    assert len(rows) == 2


def test_markdown_clean_scan():
    scan = _scan()
    scan.results = [scan.results[-1]]
    assert "No known vulnerabilities" in render_markdown(scan)


def test_html_escapes_and_is_self_contained():
    page = render_html(_scan())
    assert page.startswith("<!doctype html>")
    assert "<script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<link" not in page and "src=" not in page  # no external assets
    assert "lodash 4.17.20" in page


def test_render_report_media_types():
    scan = _scan()
    expected = {
        ReportFormat.json: ("application/json", "json"),
        ReportFormat.sarif: ("application/sarif+json", "sarif"),
        ReportFormat.cyclonedx: ("application/vnd.cyclonedx+json", "cdx.json"),
        ReportFormat.markdown: ("text/markdown; charset=utf-8", "md"),
        ReportFormat.html: ("text/html; charset=utf-8", "html"),
    }
    for fmt, (media, ext) in expected.items():
        r = render_report(scan, fmt)
        assert (r.media_type, r.extension) == (media, ext)
        if media.startswith("application/"):
            json.loads(r.body)


# ---- API -------------------------------------------------------------------


async def _fake_many(deps):
    return [
        [Vulnerability(id="GHSA-x", summary="bad", severity="HIGH", fixed_version="9")]
        if d.name == "flask"
        else []
        for d in deps
    ]


async def _fake_kev():
    return set()


@pytest.fixture
async def scan_id(monkeypatch):
    await init_db()
    monkeypatch.setattr(scanner_mod, "query_osv_many", _fake_many)
    monkeypatch.setattr(scanner_mod, "get_kev_cve_ids", _fake_kev)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post("/api/scan/text", json={"content": "flask==2.0.1\nnumpy"})
    return resp.json()["id"]


async def test_export_endpoint(scan_id):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        sarif = await ac.get(f"/api/scans/{scan_id}/report?format=sarif")
        assert sarif.status_code == 200
        assert sarif.headers["content-type"].startswith("application/sarif+json")
        assert (
            sarif.headers["content-disposition"]
            == f'attachment; filename="soteria-scan-{scan_id}.sarif"'
        )
        assert sarif.json()["runs"][0]["results"][0]["ruleId"] == "GHSA-x"

        html = await ac.get(f"/api/scans/{scan_id}/report?format=html&download=false")
        assert html.headers["content-disposition"].startswith("inline")
        assert "default-src 'none'" in html.headers["content-security-policy"]

        default = await ac.get(f"/api/scans/{scan_id}/report")
        assert default.json()["id"] == scan_id  # JSON by default

        assert (await ac.get(f"/api/scans/{scan_id}/report?format=pdf")).status_code == 422
        assert (await ac.get("/api/scans/999999/report")).status_code == 404
