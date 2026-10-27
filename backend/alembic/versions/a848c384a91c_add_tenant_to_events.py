"""add tenant to events

Revision ID: a848c384a91c
Revises: 1151f414767c
Create Date: 2026-10-05 18:52:01.432672

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a848c384a91c"
down_revision: Union[str, Sequence[str], None] = "1151f414767c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add tenant_id temporarily as nullable
    op.add_column(
        "events",
        sa.Column("tenant_id", sa.Integer(), nullable=True)
    )

    # 2. Create a development/test organization
    op.execute(
        """
        INSERT INTO organizations (name, slug, created_at)
        VALUES (
            'Sentinel Test Organization',
            'sentinel-test',
            NOW()
        )
        """
    )

    # 3. Assign existing events to the test organization
    op.execute(
        """
        UPDATE events
        SET tenant_id = (
            SELECT id
            FROM organizations
            WHERE slug = 'sentinel-test'
        )
        WHERE tenant_id IS NULL
        """
    )

    # 4. tenant_id is now required
    op.alter_column(
        "events",
        "tenant_id",
        nullable=False
    )

    # 5. Protect the relationship with a foreign key
    op.create_foreign_key(
        "fk_events_tenant_id",
        "events",
        "organizations",
        ["tenant_id"],
        ["id"]
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_events_tenant_id",
        "events",
        type_="foreignkey"
    )

    op.drop_column(
        "events",
        "tenant_id"
    )

    op.execute(
        """
        DELETE FROM organizations
        WHERE slug = 'sentinel-test'
        """
    )