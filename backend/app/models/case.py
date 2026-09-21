"""
Case ORM model representing forensic threat investigations.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(32), unique=True, index=True, nullable=False) # e.g. CASE-1042
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Risk Engine Assessment (0-100 normalized)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(24), default="INFORMATIONAL", nullable=False)
    threat_type = Column(String(32), default="SPAM_BENIGN", nullable=False)
    status = Column(String(32), default="NEW", nullable=False) # NEW, IN_PROGRESS, ESCALATED, RESOLVED
    
    # Forensic Origin (strictly objective terminology)
    probable_origin_ip = Column(String(64), nullable=True)
    origin_confidence = Column(String(24), default="LOW", nullable=False)
    approximate_location = Column(String(128), nullable=True) # e.g. "Frankfurt, Germany (AS16509)"
    
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)

    # Analyst Decision & Workflow (Separated from automated risk engine)
    analyst_decision = Column(String(32), nullable=True) # CONFIRMED_THREAT, BENIGN_FALSE_POSITIVE, NEEDS_MORE_EVIDENCE
    analyst_decision_reason = Column(Text, nullable=True)
    analyst_decision_at = Column(DateTime, nullable=True)
    analyst_decision_by = Column(String(128), nullable=True)
    escalation_reason = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    assignee = relationship("User", back_populates="cases")
    campaign = relationship("Campaign", back_populates="cases")
    emails = relationship("Email", back_populates="case", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="case", cascade="all, delete-orphan")
