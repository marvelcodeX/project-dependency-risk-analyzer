"""Schema migration tests.

Every database shape that has existed in the wild must upgrade to head with
its data intact, and the result must match the ORM models exactly. The
schemas in tests/fixtures/ were captured from the real historical code
(``create_all`` at the commits named in each file), not written by hand.
"""

import sqlite3
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import create_async_engine

import app.models  # noqa: F401
from app.core.db import Base, _upgrade, alembic_config

FIXTURES = Path(__file__).parent / "fixtures"
PHASE1_3 = (FIXTURES / "schema_phase1_3.sql").read_text()
V0_4 = (FIXTURES / "schema_v0_4.sql").read_text()
# Pre-Phase-3 databases (dev sessions only) lacked the reachability column.
PRE_PHASE3 = PHASE1_3.replace("\treachability VARCHAR(30) NOT NULL, \n", "")
assert PRE_PHASE3 != PHASE1_3
# A Phase 1-3 database later opened by v0.3/v0.4: create_all added the new
# AI cache table next to the old one.
PHASE1_3_THEN_V0_4 = PHASE1_3 + V0_4.split("CREATE TABLE scans")[0]

HEAD = ScriptDirectory.from_config(alembic_config()).get_current_head()

_SEED = """
INSERT INTO scans VALUES (1, 'requirements.txt', '2026-08-07 10:00:00', 2, 1, 43, 'HIGH');
INSERT INTO scan_dependencies VALUES (1, 1, 'flask', '2.0.1', 'PyPI', 1, '==2.0.1');
INSERT INTO scan_dependencies VALUES (2, 1, 'numpy', NULL, 'PyPI', 0, '');
INSERT INTO scan_vulnerabilities (id, scan_id, dependency_id, vuln_id, summary,
  details, aliases, severity, cvss_score, cvss_vector, fixed_version, "references",
  in_cisa_kev, risk_score, risk_level{reach_col})
  VALUES (1, 1, 1, 'GHSA-x', 's', 'd', '["CVE-1"]', 'HIGH', 7.5, NULL, '2.3.2',
  '[]', 1, 43, 'HIGH'{reach_val});
"""


def _make_db(tmp_path: Path, name: str, ddl: str | None) -> str:
    path = tmp_path / f"{name}.db"
    if ddl:
        has_reach = "reachability" in ddl
        seed = _SEED.format(
            reach_col=", reachability" if has_reach else "",
            reach_val=", 'REACHABLE'" if has_reach else "",
        )
        con = sqlite3.connect(path)
        con.executescript(ddl + seed)
        con.commit()
        con.close()
    return str(path)


async def _migrate(path: str) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade)
    await engine.dispose()


async def _diff(path: str) -> list:
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with engine.connect() as conn:
        diff = await conn.run_sync(
            lambda c: compare_metadata(MigrationContext.configure(c), Base.metadata)
        )
    await engine.dispose()
    return diff


def _query(path: str, sql: str) -> list[tuple]:
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


@pytest.mark.parametrize(
    ("name", "ddl"),
    [
        ("fresh", None),
        ("pre_phase3", PRE_PHASE3),
        ("phase1_3", PHASE1_3),
        ("phase1_3_then_v0_4", PHASE1_3_THEN_V0_4),
        ("v0_4", V0_4),
    ],
)
async def test_every_historical_schema_upgrades_to_head(tmp_path, name, ddl):
    path = _make_db(tmp_path, name, ddl)
    await _migrate(path)

    assert _query(path, "SELECT version_num FROM alembic_version") == [(HEAD,)]
    # The migrated schema is exactly what the models describe.
    assert await _diff(path) == []
    tables = {r[0] for r in _query(path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ai_explanations" not in tables  # obsolete cache dropped

    if ddl:
        # Existing rows survived; new columns read as "unknown"/defaults.
        assert _query(path, "SELECT name, version_source, depth, is_direct, depends_on "
                            "FROM scan_dependencies ORDER BY id") == [
            ("flask", "declared", None, None, None),
            ("numpy", "declared", None, None, None),
        ]
        reach = "UNKNOWN" if name == "pre_phase3" else "REACHABLE"
        assert _query(path, "SELECT vuln_id, in_cisa_kev, reachability, cwe_ids, "
                            "has_public_exploit FROM scan_vulnerabilities") == [
            ("GHSA-x", 1, reach, None, 0),
        ]


async def test_upgrade_is_idempotent(tmp_path):
    path = _make_db(tmp_path, "twice", V0_4)
    await _migrate(path)
    await _migrate(path)  # every app restart runs this
    assert _query(path, "SELECT version_num FROM alembic_version") == [(HEAD,)]


async def test_migrated_old_scan_loads_through_the_api_layer(tmp_path):
    """End to end: an old database, migrated, is readable by today's store."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services import store

    path = _make_db(tmp_path, "api", PHASE1_3)
    await _migrate(path)
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        scan = await store.get_scan(session, 1)
    await engine.dispose()

    assert scan is not None
    flask = scan.results[0]
    assert flask.dependency.depth is None and flask.dependency.depends_on == []
    assert flask.vulnerabilities[0].cwe_ids == []
    assert flask.vulnerabilities[0].in_cisa_kev is True
