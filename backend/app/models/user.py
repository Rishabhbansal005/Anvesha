"""
User ORM model representing SOC analysts and investigators.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    role = Column(String(32), default="ANALYST", nullable=False) # ANALYST, SENIOR_INVESTIGATOR, ADMIN
    badge_number = Column(String(32), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    cases = relationship("Case", back_populates="assignee")
    audit_logs = relationship("AuditLog", back_populates="user")
