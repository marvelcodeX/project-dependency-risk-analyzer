"""Dependency graph + vulnerability enrichment columns.

Revision ID: 0002_graph_enrichment
Revises: 0001_baseline
Create Date: 2026-11-15

scan_dependencies
  is_direct       direct (declared by the project) vs transitive; NULL = unknown
  depth           0 = direct, 1+ = transitive hops; NULL = unknown (plan §11)
  depends_on      JSON list of "name@version" keys this package depends on
  version_source  "declared" (from the manifest) or "latest" (resolved from the
                  registry because the manifest gave no usable version)

scan_vulnerabilities
  cwe_ids             JSON list of CWE ids (e.g. "CWE-79") from OSV
  has_public_exploit  a public exploit / PoC reference exists (plan §9.2)

ai_explanations (dropped)
  The pre-v0.3 AI cache, superseded by ai_explanation_cache. Its rows lack the
  context key, so they could never be served again.

Rows from older scans keep NULL / defaults, which the app reads as "unknown".
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_graph_enrichment"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "ai_explanations" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("ai_explanations")

    with op.batch_alter_table("scan_dependencies") as batch:
        batch.add_column(sa.Column("is_direct", sa.Boolean, nullable=True))
        batch.add_column(sa.Column("depth", sa.Integer, nullable=True))
        batch.add_column(sa.Column("depends_on", sa.JSON, nullable=True))
        batch.add_column(
            sa.Column(
                "version_source", sa.String(20), nullable=False,
                server_default="declared",
            )
        )
    with op.batch_alter_table("scan_vulnerabilities") as batch:
        batch.add_column(sa.Column("cwe_ids", sa.JSON, nullable=True))
        batch.add_column(
            sa.Column(
                "has_public_exploit", sa.Boolean, nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_vulnerabilities") as batch:
        batch.drop_column("has_public_exploit")
        batch.drop_column("cwe_ids")
    with op.batch_alter_table("scan_dependencies") as batch:
        batch.drop_column("version_source")
        batch.drop_column("depends_on")
        batch.drop_column("depth")
        batch.drop_column("is_direct")
