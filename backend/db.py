from __future__ import annotations

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Float,
    Boolean,
    ForeignKey,
    DateTime,
    Text
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime
import uuid

# ---------------------------
# DATABASE SETUP
# ---------------------------

DATABASE_URL = "sqlite:///./waveframe.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # Required for SQLite
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# ---------------------------
# MODELS
# ---------------------------

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=lambda: f"org_{uuid.uuid4().hex[:10]}")
    name = Column(String, nullable=False)

    api_keys = relationship("APIKey", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=lambda: f"key_{uuid.uuid4().hex[:10]}")
    key_value = Column(String, unique=True, nullable=False)

    organization_id = Column(String, ForeignKey("organizations.id"))
    organization = relationship("Organization", back_populates="api_keys")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True, default=lambda: f"pol_{uuid.uuid4().hex[:10]}")
    name = Column(String, nullable=False)

    organization_id = Column(String, ForeignKey("organizations.id"))
    organization = relationship("Organization", back_populates="policies")

    versions = relationship("PolicyVersion", back_populates="policy", cascade="all, delete")


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id = Column(String, primary_key=True, default=lambda: f"ver_{uuid.uuid4().hex[:10]}")
    version = Column(String, nullable=False)

    compiled_contract_json = Column(Text, nullable=False)

    policy_id = Column(String, ForeignKey("policies.id"))
    policy = relationship("Policy", back_populates="versions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True)

    # Multi-tenant ownership
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=True)
    organization = relationship("Organization", back_populates="audit_logs")

    # Policy traceability
    policy_version_id = Column(String, ForeignKey("policy_versions.id"), nullable=True)

    # Actor + action
    actor = Column(String, nullable=False)
    action_type = Column(String, nullable=False)
    action_domain = Column(String, default="unknown")
    amount = Column(Float, nullable=True)

    # Decision
    allowed = Column(Boolean, nullable=False)
    risk_level = Column(String, default="low")
    reason = Column(Text, nullable=False)
    decision_trace = Column(Text, nullable=True)
    resolved_identities = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)

    # Integrity
    trace_hash = Column(String, nullable=False)

    # Timestamp
    server_timestamp = Column(DateTime, default=datetime.utcnow)

# ---------------------------
# DB HELPERS
# ---------------------------

def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
