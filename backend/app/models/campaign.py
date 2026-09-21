"""
Campaign ORM model representing threat campaigns correlating multiple cases and IOCs.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database.base import Base


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, index=True, nullable=False) # e.g. "FIN-PHISH-Q3-INVOICE"
    threat_cluster = Column(String(64), nullable=True) # e.g. "Cluster-Alpha-Lookalike"
    threat_type = Column(String(32), default="BEC", nullable=False)
    description = Column(Text, nullable=True)
    
    severity = Column(String(24), default="HIGH", nullable=False)
    confidence_score = Column(Integer, default=75, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    cases = relationship("Case", back_populates="campaign")
