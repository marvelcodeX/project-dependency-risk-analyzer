"""Tests for the CISA KEV client (parsing + graceful failure)."""

import httpx

from app.services import kev_client


class _MockResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _MockClient:
    def __init__(self, payload=None, exc=None):
        self._payload = payload
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    async def get(self, url):
        if self._exc:
            raise self._exc
        return _MockResponse(self._payload)


async def test_parses_cve_ids(monkeypatch):
    kev_client._reset_cache_for_tests()
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-1234"},
            {"cveID": "CVE-2022-5678"},
            {"notACve": "skip"},
        ]
    }
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _MockClient(payload))
    ids = await kev_client.get_kev_cve_ids(force_refresh=True)
    assert ids == {"CVE-2021-1234", "CVE-2022-5678"}


async def test_network_error_returns_empty(monkeypatch):
    kev_client._reset_cache_for_tests()
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda *a, **k: _MockClient(exc=httpx.ConnectError("down")),
    )
    ids = await kev_client.get_kev_cve_ids(force_refresh=True)
    assert ids == set()
