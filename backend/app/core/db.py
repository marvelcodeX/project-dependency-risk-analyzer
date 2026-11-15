"""Async SQLAlchemy engine, session factory, and Base.

Works with SQLite (default) or PostgreSQL depending on ``DATABASE_URL``.
"""

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(settings.database_url, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


_BACKEND_DIR = Path(__file__).resolve().parents[2]


def alembic_config():
    """Alembic config pointing at backend/migrations (works from any cwd)."""
    from alembic.config import Config

    cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    return cfg


def _upgrade(connection) -> None:
    from alembic import command

    cfg = alembic_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")


async def init_db() -> None:
    """Bring the database schema up to date by running Alembic migrations.

    Runs on startup. The baseline migration adopts databases created before
    migrations existed, so upgrading an old ``soteria.db`` is automatic.
    """
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields a session and closes it afterwards."""
    async with SessionLocal() as session:
        yield session
