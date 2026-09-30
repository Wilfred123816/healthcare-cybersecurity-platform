from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from Backend.app.database import Base


class EHREvent(Base):
    __tablename__ = "ehr_events"

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

    patient_id: Mapped[str] = mapped_column(
        String(60),
        nullable=False
    )

    user_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("users.user_id"),
        nullable=False
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    action: Mapped[str] = mapped_column(
        String(50),
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