"""patches.base_snapshot_id

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-21 16:00:00
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("patches") as batch:
        batch.add_column(sa.Column("base_snapshot_id", sa.String(length=36), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("patches") as batch:
        batch.drop_column("base_snapshot_id")
