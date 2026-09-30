from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from Backend.app.database import Base


class IdentityEvent(Base):
    __tablename__ = "identity_events"

    event_id: Mapped[str] = mapped_column(
        String(60),
        primary_key=True
    )

    scenario_id: Mapped[str] = mapped_column(
        String(60),
        nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False
    )

    user_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("users.user_id"),
        nullable=False
    )

    device_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("devices.device_id"),
        nullable=False
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False
    )

    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False
    )

    label: Mapped[str] = mapped_column(
        String(30),
        nullable=False
    )

    attack_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )