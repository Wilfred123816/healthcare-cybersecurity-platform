from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from Backend.app.database import Base


class GroundTruth(Base):
    __tablename__ = "ground_truth"

    event_id: Mapped[str] = mapped_column(
        String(60),
        primary_key=True
    )

    scenario_id: Mapped[str] = mapped_column(
        String(60),
        nullable=False
    )

    event_source: Mapped[str] = mapped_column(
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