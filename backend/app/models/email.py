"""
Email ORM model representing parsed email messages and header forensic records.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.base import Base


class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    
    # Core Header Attributes
    message_id = Column(String(255), index=True, nullable=True)
    subject = Column(String(512), nullable=False)
    sender = Column(String(255), nullable=False, index=True)          # From header
    return_path = Column(String(255), nullable=True)                  # Return-Path
    reply_to = Column(String(255), nullable=True)                     # Reply-To
    recipient = Column(String(255), nullable=False)                   # To header
    
    # Forensic Checksums
    body_hash_sha256 = Column(String(64), nullable=True)
    header_hash_sha256 = Column(String(64), nullable=True)
    
    # Authentication Results
    spf_status = Column(String(24), default="NONE", nullable=False)   # PASS, FAIL, SOFTFAIL, NONE
    dkim_status = Column(String(24), default="NONE", nullable=False)
    dmarc_status = Column(String(24), default="NONE", nullable=False)
    
    # Parsed Routing Data
    relay_count = Column(Integer, default=0, nullable=False)
    observed_relays_json = Column(JSON, nullable=True)                # Structured list of observed Received hops
    raw_headers = Column(Text, nullable=True)
    
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="emails")
