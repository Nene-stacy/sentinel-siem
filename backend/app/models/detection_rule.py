
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "name",
            name="uq_detection_rules_organization_name",
        ),
        CheckConstraint(
            "threshold >= 1",
            name="ck_detection_rules_threshold_positive",
        ),
        CheckConstraint(
            "window_minutes >= 1",
            name="ck_detection_rules_window_positive",
        ),
        CheckConstraint(
            "severity >= 1 AND severity <= 5",
            name="ck_detection_rules_severity_range",
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
        String(150),
        nullable=False,
    )

    rule_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="repeated_failed_logins",
    )

    threshold: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=5,
    )

    window_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=5,
    )

    severity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=4,
    )

    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
