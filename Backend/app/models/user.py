from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from Backend.app.database import Base


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(
        String(50),
        primary_key=True
    )

    department: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    role: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )