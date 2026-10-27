"""Credentials used by external security integrations."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class IntegrationCredential(Base):
    """An organization-scoped credential for an external integration."""

    __tablename__ = "integration_credentials"

    __table_args__ = (
        UniqueConstraint(
            "key_prefix",
            name="uq_integration_credentials_key_prefix",
        ),
        UniqueConstraint(
            "organization_id",
            "name",
            name="uq_integration_credentials_org_name",
        ),
    )

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="wazuh",
    )

    # Identifies a key without storing or exposing the full secret.
    key_prefix: Mapped[str] = mapped_column(
        String(12),
        nullable=False,
    )

    # SHA-256 hash of the full, randomly generated integration key.
    key_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )