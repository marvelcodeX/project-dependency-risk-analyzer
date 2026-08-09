"""Async SQLAlchemy engine, session factory, and Base.

Works with SQLite (default) or PostgreSQL depending on ``DATABASE_URL``.
"""

from collections.abc import AsyncIterator

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


async def init_db() -> None:
    """Create tables if they don't exist. Fine for SQLite / dev; production
    Postgres would use Alembic migrations instead."""
    # Import models so they're registered on Base.metadata before create_all.
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields a session and closes it afterwards."""
    async with SessionLocal() as session:
        yield session
