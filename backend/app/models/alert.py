from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "deduplication_key",
            name="uq_alerts_tenant_deduplication_key",
        ),
    )

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("events.id"),
        nullable=True,
    )

        # Links a recurring incident to the alert that preceded it.
    previous_alert_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "alerts.id",
            ondelete="SET NULL",
            name="fk_alerts_previous_alert_id_alerts",
        ),
        nullable=True,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    source_alert_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # Identifies the rule and source responsible for this alert.
    deduplication_key: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    rule_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    severity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="OPEN",
    )

    # When SEER's detection engine triggered this alert.
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # When the alert record was created in the database.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )