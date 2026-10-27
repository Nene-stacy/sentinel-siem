"""add alert deduplication key

Revision ID: 0fce369ab0f7
Revises: f904662b287f
Create Date: 2026-10-11 15:48:00.503540

"""


"""Add alert deduplication key."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# Revision identifiers, used by Alembic.
revision: str = "0fce369ab0f7"
down_revision: Union[str, Sequence[str], None] = "f904662b287f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add a key that prevents duplicate alerts within an organization."""

    op.add_column(
        "alerts",
        sa.Column(
            "deduplication_key",
            sa.String(length=255),
            nullable=True,
        ),
    )

    op.create_unique_constraint(
        "uq_alerts_tenant_deduplication_key",
        "alerts",
        ["tenant_id", "deduplication_key"],
    )


def downgrade() -> None:
    """Remove the deduplication constraint and column."""

    op.drop_constraint(
        "uq_alerts_tenant_deduplication_key",
        "alerts",
        type_="unique",
    )

    op.drop_column("alerts", "deduplication_key")

