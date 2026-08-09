"""End-to-end API tests: scan pipeline + persistence, with OSV/KEV mocked."""

import httpx
import pytest

import app.api.scan as scan_api
from app.core.db import init_db
from app.main import app
from app.schemas.scan import Vulnerability


async def _fake_query_osv(dep):
    """Return one KEV-listed vuln for flask, nothing for anything else."""
    if dep.name == "flask":
        return [
            Vulnerability(
                id="GHSA-xxxx",
                summary="Flask session issue",
                aliases=["CVE-2023-30861"],
                severity="HIGH",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                fixed_version="2.3.2",
            )
        ]
    return []


async def _fake_kev():
    return {"CVE-2023-30861"}


@pytest.fixture(autouse=True)
async def _setup(monkeypatch):
    await init_db()
    monkeypatch.setattr(scan_api, "query_osv", _fake_query_osv)
    monkeypatch.setattr(scan_api, "get_kev_cve_ids", _fake_kev)


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


async def test_scan_enriches_persists_and_reloads():
    async with await _client() as ac:
        # Run a scan.
        resp = await ac.post(
            "/api/scan/text", json={"content": "flask==2.0.1\nnumpy"}
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["total_dependencies"] == 2
        assert data["vulnerable_dependencies"] == 1
        assert data["id"] is not None
        assert data["risk_score"] > 0
        assert data["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}

        flask = next(r for r in data["results"] if r["dependency"]["name"] == "flask")
        vuln = flask["vulnerabilities"][0]
        assert vuln["in_cisa_kev"] is True  # CVE was in our mock KEV set
        assert vuln["risk_score"] > 0
        scan_id = data["id"]

        # It shows up in the history list.
        listing = (await ac.get("/api/scans")).json()
        assert any(s["id"] == scan_id for s in listing)

        # And reloads identically from the database.
        reloaded = (await ac.get(f"/api/scans/{scan_id}")).json()
        assert reloaded["id"] == scan_id
        assert reloaded["vulnerable_dependencies"] == 1
        r_flask = next(
            r for r in reloaded["results"] if r["dependency"]["name"] == "flask"
        )
        assert r_flask["vulnerabilities"][0]["in_cisa_kev"] is True


async def test_missing_scan_returns_404():
    async with await _client() as ac:
        assert (await ac.get("/api/scans/999999")).status_code == 404


async def test_reachability_from_source_raises_risk():
    async with await _client() as ac:
        # Without source → UNKNOWN.
        no_src = (
            await ac.post("/api/scan/text", json={"content": "flask==2.0.1"})
        ).json()
        v_unknown = no_src["results"][0]["vulnerabilities"][0]
        assert v_unknown["reachability"] == "UNKNOWN"

        # With source that imports flask → REACHABLE and higher risk.
        with_src = (
            await ac.post(
                "/api/scan/text",
                json={
                    "content": "flask==2.0.1",
                    "source_files": {"app.py": "import flask\n"},
                },
            )
        ).json()
        v_reach = with_src["results"][0]["vulnerabilities"][0]
        assert v_reach["reachability"] == "REACHABLE"
        assert v_reach["risk_score"] > v_unknown["risk_score"]
