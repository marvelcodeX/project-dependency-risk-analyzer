"""Tests for resolving unversioned dependencies against PyPI / npm."""

import pytest

from app.schemas.scan import Dependency
from app.services import registry

PYPI_DOC = {
    "releases": {
        "1.26.18": [{"yanked": False}],
        "1.26.20": [{"yanked": False}],
        "2.0.0": [{"yanked": False}],
        "2.2.0": [{"yanked": False}],
        "2.3.0rc1": [{"yanked": False}],  # pre-release: never picked
        "2.2.9": [{"yanked": True}],  # every file yanked
        "2.2.5": [],  # no artifacts
        "bogus": [{"yanked": False}],
    }
}


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("", "2.2.0"),
        ("<2", "1.26.20"),
        ("!=2.2.0", "2.0.0"),
        ("<1", None),
        ("(<2)", "1.26.20"),  # old parenthesized form
        ("not a spec", None),
    ],
)
def test_pick_pypi_version(spec, expected):
    assert registry.pick_pypi_version(PYPI_DOC, spec) == expected


@pytest.mark.parametrize(
    ("dep", "expected"),
    [
        (Dependency(name="numpy"), True),
        (Dependency(name="urllib3", raw_spec="<2"), True),
        (Dependency(name="flask", version="2.0.1"), False),
        (Dependency(name="pkg", raw_spec="@ https://x/y.zip"), False),
        (Dependency(name="lodash", ecosystem="npm", raw_spec="*"), True),
        (Dependency(name="lodash", ecosystem="npm", raw_spec=""), True),
        (Dependency(name="local", ecosystem="npm", raw_spec="file:../x"), False),
        (Dependency(name="chalk", ecosystem="npm", raw_spec="<5"), False),
        (Dependency(name="g", ecosystem="Go"), False),
        (Dependency(name="a:b", ecosystem="Maven"), False),
    ],
)
def test_needs_resolution(dep, expected):
    assert registry.needs_resolution(dep) is expected


async def test_resolve_unversioned_fills_versions(monkeypatch):
    calls = []

    async def fake(client, url):
        calls.append(url)
        if "pypi.org/pypi/numpy" in url:
            return PYPI_DOC
        if "registry.npmjs.org/lodash/latest" in url:
            return {"version": "4.17.21"}
        return None  # unknown package / registry down

    monkeypatch.setattr(registry, "_fetch_json", fake)
    deps = [
        Dependency(name="numpy"),
        Dependency(name="lodash", ecosystem="npm", raw_spec="*"),
        Dependency(name="ghost"),
        Dependency(name="flask", version="2.0.1", pinned=True),
    ]
    await registry.resolve_unversioned(deps)

    numpy, lodash, ghost, flask = deps
    assert (numpy.version, numpy.version_source, numpy.pinned) == ("2.2.0", "latest", False)
    assert (lodash.version, lodash.version_source) == ("4.17.21", "latest")
    assert ghost.version is None and ghost.version_source == "declared"  # soft fail
    assert flask.version_source == "declared"
    assert len(calls) == 3  # pinned deps never hit the registry
