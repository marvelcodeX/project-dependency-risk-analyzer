"""Tests for the OSV client (HTTP mocked with httpx.MockTransport)."""

import httpx
import pytest

from app.schemas.scan import Dependency
from app.services import osv_client
from app.services.osv_client import OsvError, _extract_fixed_version, query_osv
from app.services.versions import less_than


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ---- fixed-version selection -----------------------------------------------


# Django-style advisory with one affected range per release branch.
_MULTI_BRANCH = {
    "affected": [
        {
            "package": {"name": "Django", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "3.2"},
                        {"fixed": "3.2.19"},
                        {"introduced": "4.0"},
                        {"fixed": "4.0.10"},
                        {"introduced": "4.1"},
                        {"fixed": "4.1.7"},
                    ],
                },
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
            ],
        },
        {
            "package": {"name": "other-pkg", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "99.0"}]}],
        },
    ]
}


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("3.2.5", "3.2.19"),
        ("4.0.1", "4.0.10"),
        ("4.1", "4.1.7"),
        (None, "4.1.7"),  # unknown version → highest fix, safe for all
        ("5.0", "4.1.7"),  # not in any range → still highest
    ],
)
def test_fixed_version_matches_installed_branch(version, expected):
    dep = Dependency(name="django", version=version)
    assert _extract_fixed_version(_MULTI_BRANCH, dep) == expected


def test_fixed_version_none_when_unfixed():
    vuln = {
        "affected": [
            {
                "package": {"name": "x", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ]
    }
    assert _extract_fixed_version(vuln, Dependency(name="x", version="1.0")) is None


def test_fixed_version_semver_prerelease():
    vuln = {
        "affected": [
            {
                "package": {"name": "pkg", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "2.0.0-rc.2"}],
                    }
                ],
            }
        ]
    }
    dep = Dependency(name="pkg", version="2.0.0-rc.1", ecosystem="npm")
    assert _extract_fixed_version(vuln, dep) == "2.0.0-rc.2"


def test_version_ordering():
    assert less_than("1.9", "1.10", "PyPI")
    assert less_than("2.0.0rc1", "2.0.0", "PyPI")
    assert less_than("1.2.3-beta", "1.2.3", "npm")
    assert less_than("v1.2.3", "1.10.0", "Go")
    assert not less_than("1.2.0", "1.2", "npm")
    assert less_than("2.14.1", "2.15.0", "Maven")


# ---- query_osv HTTP behaviour ----------------------------------------------


async def test_query_osv_follows_pagination():
    seen_tokens = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        if "page_token" in body:
            seen_tokens.append(True)
            return httpx.Response(200, json={"vulns": [{"id": "OSV-2"}]})
        return httpx.Response(
            200, json={"vulns": [{"id": "OSV-1"}], "next_page_token": "t1"}
        )

    async with _client(handler) as c:
        vulns = await query_osv(Dependency(name="x", version="1"), c)
    assert [v.id for v in vulns] == ["OSV-1", "OSV-2"]
    assert seen_tokens == [True]


async def test_query_osv_raises_on_server_error():
    async with _client(lambda r: httpx.Response(503)) as c:
        with pytest.raises(OsvError):
            await query_osv(Dependency(name="x", version="1"), c)


async def test_query_osv_raises_on_network_error():
    def handler(request):
        raise httpx.ConnectError("refused")

    async with _client(handler) as c:
        with pytest.raises(OsvError):
            await query_osv(Dependency(name="x", version="1"), c)


async def test_query_osv_client_error_means_no_data():
    async with _client(lambda r: httpx.Response(400)) as c:
        assert await query_osv(Dependency(name="x", version="bad"), c) == []


async def test_query_osv_many_preserves_order(monkeypatch):
    async def fake(dep, client):
        return [] if dep.name == "a" else [osv_client.Vulnerability(id=dep.name, summary="")]

    monkeypatch.setattr(osv_client, "query_osv", fake)
    out = await osv_client.query_osv_many(
        [Dependency(name=n) for n in ("a", "b", "c")]
    )
    assert [[v.id for v in vs] for vs in out] == [[], ["b"], ["c"]]
