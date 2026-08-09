"""ORM model for cached AI explanations.

Keyed by (vuln_id, model) so the same advisory's explanation is reused across
scans instead of being regenerated every time (plan section 13, caching).
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AiExplanationCache(Base):
    __tablename__ = "ai_explanations"
    __table_args__ = (UniqueConstraint("vuln_id", "model", name="uq_vuln_model"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vuln_id: Mapped[str] = mapped_column(String(100), index=True)
    model: Mapped[str] = mapped_column(String(100))

    summary: Mapped[str] = mapped_column(String, default="")
    attack_scenario: Mapped[str] = mapped_column(String, default="")
    project_impact: Mapped[str] = mapped_column(String, default="")
    fix_steps: Mapped[str] = mapped_column(String, default="")
    priority: Mapped[str] = mapped_column(String(30), default="MONITOR")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
