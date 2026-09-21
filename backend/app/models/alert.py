"""
Alert ORM model representing threat notifications for Web & Mobile triage.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(24), default="INFORMATIONAL", nullable=False)
    threat_type = Column(String(32), default="SPAM_BENIGN", nullable=False)
    
    is_reviewed = Column(Boolean, default=False, nullable=False)
    is_escalated = Column(Boolean, default=False, nullable=False)
    fcm_message_id = Column(String(128), nullable=True) # Mobile push notification reference
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="alerts")
