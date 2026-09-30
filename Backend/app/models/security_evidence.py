from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from Backend.app.database import Base


class SecurityEvidence(Base):
    __tablename__ = "security_evidence"

    evidence_id: Mapped[str] = mapped_column(
        String(60),
        primary_key=True
    )

    event_id: Mapped[str] = mapped_column(
        String(60),
        nullable=False,
        index=True
    )

    scenario_id: Mapped[str] = mapped_column(
        String(60),
        nullable=False
    )

    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    provenance: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    integrity_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    freshness_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    consistency_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    is_poisoned: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False
    )

    poison_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )