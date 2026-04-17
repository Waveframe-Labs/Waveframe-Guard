from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Generator

from sqlalchemy import (
    create_engine,
    String,
    Integer,
    ForeignKey,
    DateTime,
    Boolean,
    Text,
    JSON,
)
from sqlalchemy.orm import (
    declarative_base,
    relationship,
    sessionmaker,
    Mapped,
    mapped_column,
)

# ---------------------------
# DATABASE CONFIG
# ---------------------------

DATABASE_URL = "sqlite:///./waveframe.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # required for SQLite
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

Base = declarative_base()


# ---------------------------
# MODELS
# ---------------------------

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    billing_tier: Mapped[str] = mapped_column(String, default="free")

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # relationships
    api_keys = relationship("APIKey", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    key_hash: Mapped[str] = mapped_column(String, unique=True, index=True)

    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # relationships
    organization = relationship("Organization", back_populates="api_keys")


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id")
    )

    name: Mapped[str] = mapped_column(String, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # relationships
    organization = relationship("Organization", back_populates="policies")
    versions = relationship("PolicyVersion", back_populates="policy")


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    policy_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("policies.id")
    )

    version_number: Mapped[str] = mapped_column(String, nullable=False)

    raw_rules_json: Mapped[dict] = mapped_column(JSON)

    compiled_hash: Mapped[str] = mapped_column(String, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # relationships
    policy = relationship("Policy", back_populates="versions")
    audit_logs = relationship("AuditLog", back_populates="policy_version")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    decision_id: Mapped[str] = mapped_column(String, index=True)

    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id")
    )

    policy_version_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("policy_versions.id")
    )

    actor: Mapped[str] = mapped_column(String)

    action: Mapped[dict] = mapped_column(JSON)

    allowed: Mapped[bool] = mapped_column(Boolean)

    reason: Mapped[str] = mapped_column(Text)

    trace_hash: Mapped[str] = mapped_column(String)

    server_timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # relationships
    organization = relationship("Organization", back_populates="audit_logs")
    policy_version = relationship("PolicyVersion", back_populates="audit_logs")


# ---------------------------
# HELPERS
# ---------------------------

def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


# ---------------------------
# INIT
# ---------------------------

def init_db() -> None:
    Base.metadata.create_all(bind=engine)