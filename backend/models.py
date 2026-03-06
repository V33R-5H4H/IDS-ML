# backend/models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from backend.database import Base   # ← only direction: models → database


class User(Base):
    __tablename__ = "users"
    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String,  unique=True, index=True, nullable=False)
    email           = Column(String,  unique=True, index=True, nullable=False)
    display_name    = Column(String,  nullable=True)
    hashed_password = Column(String,  nullable=False)
    role            = Column(String,  default="viewer")
    is_active       = Column(Boolean, default=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    last_login      = Column(DateTime(timezone=True), nullable=True)


class RoleRequest(Base):
    __tablename__ = "role_requests"
    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    username       = Column(String, nullable=False)
    current_role   = Column(String, nullable=False)
    requested_role = Column(String, nullable=False)
    reason         = Column(Text,   nullable=True)
    status         = Column(String, default="pending")   # pending | approved | rejected
    created_at     = Column(DateTime(timezone=True), server_default=func.now())
    reviewed_at    = Column(DateTime(timezone=True), nullable=True)
    reviewed_by    = Column(String, nullable=True)
