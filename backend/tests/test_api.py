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


async def _fake_query_osv_many(deps):
    return [await _fake_query_osv(d) for d in deps]


async def _fake_kev():
    return {"CVE-2023-30861"}


@pytest.fixture(autouse=True)
async def _setup(monkeypatch):
    await init_db()
    monkeypatch.setattr(scan_api, "query_osv_many", _fake_query_osv_many)
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


async def test_unsupported_or_broken_manifest_returns_400():
    async with await _client() as ac:
        resp = await ac.post(
            "/api/scan/text",
            json={"content": "{not json", "filename": "package.json"},
        )
        assert resp.status_code == 400
        assert "Invalid JSON" in resp.json()["detail"]

        resp = await ac.post(
            "/api/scan/text", json={"content": "x", "filename": "Gemfile.lock"}
        )
        assert resp.status_code == 400
        assert "Unsupported" in resp.json()["detail"]


async def test_osv_outage_returns_502_not_empty_results(monkeypatch):
    async def _down(deps):
        raise scan_api.OsvError("connection refused")

    monkeypatch.setattr(scan_api, "query_osv_many", _down)
    async with await _client() as ac:
        resp = await ac.post("/api/scan/text", json={"content": "flask==2.0.1"})
    assert resp.status_code == 502
    assert "OSV" in resp.json()["detail"]


async def test_pasted_package_json_is_detected_and_labelled():
    async with await _client() as ac:
        data = (
            await ac.post(
                "/api/scan/text",
                json={
                    "content": '{"dependencies": {"lodash": "^4.17.20"}}',
                    "filename": "pasted",
                },
            )
        ).json()
    assert data["filename"] == "package.json"
    dep = data["results"][0]["dependency"]
    assert dep["ecosystem"] == "npm"
    assert dep["version"] == "4.17.20"


async def test_upload_rejects_non_utf8_and_accepts_bom():
    async with await _client() as ac:
        bad = await ac.post(
            "/api/scan/file",
            files={"file": ("requirements.txt", b"\xff\xfe\x00bad", "text/plain")},
        )
        assert bad.status_code == 400

        good = await ac.post(
            "/api/scan/file",
            files={"file": ("requirements.txt", "\ufeffflask==2.0.1".encode(), "text/plain")},
        )
        assert good.status_code == 200
        assert good.json()["results"][0]["dependency"]["name"] == "flask"


async def test_upload_with_source_files_sets_reachability():
    async with await _client() as ac:
        resp = await ac.post(
            "/api/scan/file",
            files=[
                ("file", ("requirements.txt", b"flask==2.0.1", "text/plain")),
                ("source_files", ("app.py", b"import flask\n", "text/x-python")),
            ],
        )
    assert resp.status_code == 200
    vuln = resp.json()["results"][0]["vulnerabilities"][0]
    assert vuln["reachability"] == "REACHABLE"
