"""ORM model for cached AI explanations.

Keyed by (vuln_id, model, context_key) so an explanation is reused across
scans instead of being regenerated every time (plan section 13, caching).
``context_key`` hashes everything else the prompt depends on (package version,
reachability, KEV status, ...): the same advisory seen in a different context
needs a different "project impact" and priority.

The table was renamed from ``ai_explanations`` when context_key was added, so
``create_all`` builds the new shape without a migration; the old table is just
a stale cache and can be dropped.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AiExplanationCache(Base):
    __tablename__ = "ai_explanation_cache"
    __table_args__ = (
        UniqueConstraint("vuln_id", "model", "context_key", name="uq_vuln_model_ctx"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    vuln_id: Mapped[str] = mapped_column(String(100), index=True)
    model: Mapped[str] = mapped_column(String(100))
    context_key: Mapped[str] = mapped_column(String(64), default="")

    summary: Mapped[str] = mapped_column(String, default="")
    attack_scenario: Mapped[str] = mapped_column(String, default="")
    project_impact: Mapped[str] = mapped_column(String, default="")
    fix_steps: Mapped[str] = mapped_column(String, default="")
    priority: Mapped[str] = mapped_column(String(30), default="MONITOR")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
