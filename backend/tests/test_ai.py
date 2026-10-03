"""Tests for the AI explanation layer (Ollama mocked — no real LLM needed)."""

import httpx
import pytest

import app.services.ollama_client as ollama_client
from app.core.db import init_db
from app.main import app
from app.schemas.ai import AiExplanation, ExplainRequest


# ---- pure parsing / schema logic -------------------------------------------


def test_parse_valid_json():
    content = (
        '{"summary":"s","attack_scenario":"a","project_impact":"i",'
        '"fix_steps":"f","priority":"fix now"}'
    )
    exp = ollama_client._parse(content)
    assert exp.summary == "s"
    assert exp.priority == "FIX_NOW"  # normalized from "fix now"


def test_parse_invalid_json_falls_back_to_summary():
    exp = ollama_client._parse("not json at all")
    assert exp.summary == "not json at all"
    assert exp.priority == "MONITOR"


def test_parse_coerces_list_field_to_text():
    # Models often return fix_steps as an array of steps.
    content = '{"summary":"s","fix_steps":["Upgrade flask","Run pip install"]}'
    exp = ollama_client._parse(content)
    assert exp.fix_steps == "Upgrade flask\nRun pip install"
    assert "[" not in exp.fix_steps  # not a Python list repr


def test_priority_unknown_becomes_monitor():
    assert AiExplanation(
        summary="x", attack_scenario="", project_impact="", fix_steps="",
        priority="whenever",
    ).priority == "MONITOR"


# ---- API endpoints ---------------------------------------------------------


def _req() -> dict:
    return ExplainRequest(
        vuln_id="GHSA-test", package="flask", version="2.0.1", severity="HIGH"
    ).model_dump()


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


@pytest.fixture(autouse=True)
async def _db():
    await init_db()


async def test_status_reports_unavailable(monkeypatch):
    async def _no():
        return False

    monkeypatch.setattr(ollama_client, "is_available", _no)
    async with await _client() as ac:
        data = (await ac.get("/api/ai/status")).json()
    assert data["available"] is False
    assert data["detail"]


async def test_explain_generates_then_caches(monkeypatch):
    calls = {"n": 0}

    async def _gen(req):
        calls["n"] += 1
        return AiExplanation(
            summary="Flask session flaw",
            attack_scenario="An attacker could forge a cookie.",
            project_impact="Sessions could be hijacked.",
            fix_steps="Upgrade to 2.3.2.",
            priority="FIX_THIS_WEEK",
        )

    monkeypatch.setattr(ollama_client, "generate", _gen)

    async with await _client() as ac:
        first = (await ac.post("/api/ai/explain", json=_req())).json()
        assert first["cached"] is False
        assert first["priority"] == "FIX_THIS_WEEK"

        second = (await ac.post("/api/ai/explain", json=_req())).json()
        assert second["cached"] is True  # served from DB cache
        assert second["summary"] == "Flask session flaw"

    assert calls["n"] == 1  # LLM invoked only once


async def test_explain_returns_503_when_unavailable(monkeypatch):
    async def _boom(req):
        raise ollama_client.OllamaError("connection refused")

    monkeypatch.setattr(ollama_client, "generate", _boom)
    async with await _client() as ac:
        resp = await ac.post(
            "/api/ai/explain", json={**_req(), "vuln_id": "GHSA-down"}
        )
    assert resp.status_code == 503
    assert "unavailable" in resp.json()["detail"].lower()


async def test_cache_is_keyed_by_finding_context(monkeypatch):
    calls = {"n": 0}

    async def _gen(req):
        calls["n"] += 1
        return AiExplanation(
            summary=f"reach={req.reachability}",
            attack_scenario="", project_impact="", fix_steps="",
        )

    monkeypatch.setattr(ollama_client, "generate", _gen)
    base = {**_req(), "vuln_id": "GHSA-ctx"}

    async with await _client() as ac:
        a = (await ac.post("/api/ai/explain", json=base)).json()
        b = (
            await ac.post(
                "/api/ai/explain", json={**base, "reachability": "UNREACHABLE"}
            )
        ).json()
        again = (await ac.post("/api/ai/explain", json=base)).json()

    # Different reachability → separate explanation, not the cached one.
    assert b["cached"] is False
    assert b["summary"] == "reach=UNREACHABLE"
    assert again["cached"] is True and again["summary"] == "reach=UNKNOWN"
    assert a["summary"] == "reach=UNKNOWN"
    assert calls["n"] == 2


async def test_force_regenerates_and_replaces_cache(monkeypatch):
    version = {"n": 0}

    async def _gen(req):
        version["n"] += 1
        return AiExplanation(
            summary=f"v{version['n']}",
            attack_scenario="", project_impact="", fix_steps="",
        )

    monkeypatch.setattr(ollama_client, "generate", _gen)
    body = {**_req(), "vuln_id": "GHSA-force"}

    async with await _client() as ac:
        await ac.post("/api/ai/explain", json=body)
        forced = (await ac.post("/api/ai/explain?force=true", json=body)).json()
        after = (await ac.post("/api/ai/explain", json=body)).json()

    assert forced["summary"] == "v2" and forced["cached"] is False
    assert after["cached"] is True
    assert after["summary"] == "v2"  # the regenerated text was persisted
