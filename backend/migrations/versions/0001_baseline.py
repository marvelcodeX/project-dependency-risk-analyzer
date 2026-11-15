"""Baseline: the schema as of v0.4.0 (before migrations existed).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-15

Databases created before Alembic was added were built by ``create_all`` and
have no ``alembic_version`` table. This migration therefore *reconciles*
instead of blindly creating: it creates any missing table and adds any
missing column, so all of these end up identical:

- a brand-new database,
- a v0.4.0 database (everything present → no-op),
- a Phase 1–3 database (no ``ai_explanation_cache``),
- a pre-Phase-3 database (no ``scan_vulnerabilities.reachability``).

The table definitions below are a frozen snapshot. Never import the ORM
models here: they keep changing, and this migration must not.
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def _tables() -> list[sa.Table]:
    md = sa.MetaData()
    tz = sa.DateTime(timezone=True)
    return [
        sa.Table(
            "scans", md,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("filename", sa.String(255), nullable=False,
                      server_default="requirements.txt"),
            sa.Column("created_at", tz, nullable=False,
                      server_default=sa.func.current_timestamp()),
            sa.Column("total_dependencies", sa.Integer, nullable=False, server_default="0"),
            sa.Column("vulnerable_dependencies", sa.Integer, nullable=False, server_default="0"),
            sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
            sa.Column("risk_level", sa.String(20), nullable=False, server_default="NONE"),
        ),
        sa.Table(
            "scan_dependencies", md,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("scan_id", sa.Integer,
                      sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("version", sa.String(100), nullable=True),
            sa.Column("ecosystem", sa.String(50), nullable=False, server_default="PyPI"),
            sa.Column("pinned", sa.Boolean, nullable=False, server_default=sa.false()),
            sa.Column("raw_spec", sa.String(255), nullable=False, server_default=""),
        ),
        sa.Table(
            "scan_vulnerabilities", md,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("scan_id", sa.Integer,
                      sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("dependency_id", sa.Integer,
                      sa.ForeignKey("scan_dependencies.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("vuln_id", sa.String(100), nullable=False),
            sa.Column("summary", sa.String, nullable=False, server_default=""),
            sa.Column("details", sa.String, nullable=False, server_default=""),
            sa.Column("aliases", sa.JSON, nullable=False),
            sa.Column("severity", sa.String(20), nullable=False, server_default="UNKNOWN"),
            sa.Column("cvss_score", sa.Float, nullable=True),
            sa.Column("cvss_vector", sa.String(200), nullable=True),
            sa.Column("fixed_version", sa.String(200), nullable=True),
            sa.Column("references", sa.JSON, nullable=False),
            sa.Column("in_cisa_kev", sa.Boolean, nullable=False, server_default=sa.false()),
            sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
            sa.Column("risk_level", sa.String(20), nullable=False, server_default="NONE"),
            sa.Column("reachability", sa.String(30), nullable=False, server_default="UNKNOWN"),
        ),
        sa.Table(
            "ai_explanation_cache", md,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("vuln_id", sa.String(100), nullable=False, index=True),
            sa.Column("model", sa.String(100), nullable=False),
            sa.Column("context_key", sa.String(64), nullable=False, server_default=""),
            sa.Column("summary", sa.String, nullable=False, server_default=""),
            sa.Column("attack_scenario", sa.String, nullable=False, server_default=""),
            sa.Column("project_impact", sa.String, nullable=False, server_default=""),
            sa.Column("fix_steps", sa.String, nullable=False, server_default=""),
            sa.Column("priority", sa.String(30), nullable=False, server_default="MONITOR"),
            sa.Column("created_at", tz, nullable=False,
                      server_default=sa.func.current_timestamp()),
            sa.UniqueConstraint("vuln_id", "model", "context_key", name="uq_vuln_model_ctx"),
        ),
    ]


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = set(insp.get_table_names())

    for table in _tables():  # ordered so foreign keys resolve
        if table.name not in existing:
            table.create(bind)
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        missing = [c for c in table.columns if c.name not in have]
        if missing:
            with op.batch_alter_table(table.name) as batch:
                for col in missing:
                    # Existing rows need a value: server_default supplies it.
                    default = col.server_default.arg if col.server_default else None
                    batch.add_column(
                        sa.Column(col.name, col.type, nullable=col.nullable,
                                  server_default=default)
                    )


def downgrade() -> None:
    # Dropping the baseline would delete all scan history; refuse.
    raise RuntimeError("The baseline migration cannot be downgraded.")
