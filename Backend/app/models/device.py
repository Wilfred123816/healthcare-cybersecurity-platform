from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from Backend.app.database import Base


class Device(Base):
    __tablename__ = "devices"

    device_id: Mapped[str] = mapped_column(
        String(50),
        primary_key=True
    )

    device_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )