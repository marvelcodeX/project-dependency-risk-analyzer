"""Shared test setup.

Point the app at a throwaway SQLite database *before* app.core.config is
imported anywhere, so tests never touch a real dev database.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp.name}"

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_registry_network(monkeypatch):
    """Tests never call PyPI/npm: version resolution sees "registry unreachable"
    (the scanner then falls back to versionless lookups). Tests of the
    resolver itself patch ``_fetch_json`` explicitly."""
    from app.services import registry

    async def _offline(client, url):
        return None

    monkeypatch.setattr(registry, "_fetch_json", _offline)
