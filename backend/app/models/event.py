from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )
    
    tenant_id: Mapped[int] = mapped_column(
    ForeignKey("organizations.id"),
    nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    source: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    severity: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )