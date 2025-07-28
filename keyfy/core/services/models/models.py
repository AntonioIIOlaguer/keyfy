from sqlalchemy import JSON, Column, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import (
    Mapped,
    attribute_mapped_collection,
    declarative_base,
    mapped_column,
    relationship,
)

Base = declarative_base()


class User(Base):
    """
    A user class containing username and password to compartmentalize
    different vaults containing credentials
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )  # hashed password
    auth_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    vault_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    vault: Mapped[dict[str, "Credential"]] = relationship(
        "Credential",
        back_populates="owner",
        cascade="all, delete-orphan",
        collection_class=attribute_mapped_collection("key"),
    )


class Credential(Base):
    """
    Contains the credentials of a user. Password is encrypted in
    AES-GCM using a derived key from a master password using PBKDF2
    """

    __tablename__ = "Credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String, nullable=False)  # e.g., "github", "gmail"
    username: Mapped[str] = mapped_column(String, nullable=False)
    password: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )  # Encrypted: salt, iv, ciphertext

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    owner: Mapped["User"] = relationship("User", back_populates="vault")
