"""SQLAlchemy ORM models for persisted scans.

A pragmatic subset of the schema in the project plan — enough to store a scan
and reload its full results. UUIDs are swapped for autoincrement integer keys
to stay portable across SQLite and PostgreSQL.
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), default="requirements.txt")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    total_dependencies: Mapped[int] = mapped_column(default=0)
    vulnerable_dependencies: Mapped[int] = mapped_column(default=0)
    # Overall project risk = the highest per-vuln risk score in the scan.
    risk_score: Mapped[int] = mapped_column(default=0)
    risk_level: Mapped[str] = mapped_column(String(20), default="NONE")

    dependencies: Mapped[list["ScanDependency"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanDependency.id",
    )
    vulnerabilities: Mapped[list["ScanVulnerability"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanVulnerability.risk_score.desc()",
    )


class ScanDependency(Base):
    __tablename__ = "scan_dependencies"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ecosystem: Mapped[str] = mapped_column(String(50), default="PyPI")
    pinned: Mapped[bool] = mapped_column(default=False)
    raw_spec: Mapped[str] = mapped_column(String(255), default="")

    scan: Mapped["Scan"] = relationship(back_populates="dependencies")
    vulnerabilities: Mapped[list["ScanVulnerability"]] = relationship(
        back_populates="dependency",
        cascade="all, delete-orphan",
    )


class ScanVulnerability(Base):
    __tablename__ = "scan_vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    dependency_id: Mapped[int] = mapped_column(
        ForeignKey("scan_dependencies.id", ondelete="CASCADE")
    )

    vuln_id: Mapped[str] = mapped_column(String(100))  # OSV id
    summary: Mapped[str] = mapped_column(String, default="")
    details: Mapped[str] = mapped_column(String, default="")
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)

    in_cisa_kev: Mapped[bool] = mapped_column(default=False)
    risk_score: Mapped[int] = mapped_column(default=0)
    risk_level: Mapped[str] = mapped_column(String(20), default="NONE")
    reachability: Mapped[str] = mapped_column(String(30), default="UNKNOWN")

    scan: Mapped["Scan"] = relationship(back_populates="vulnerabilities")
    dependency: Mapped["ScanDependency"] = relationship(
        back_populates="vulnerabilities"
    )
