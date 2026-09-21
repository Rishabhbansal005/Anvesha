"""
Evidence ORM model representing append-only cryptographic evidence ledger with hash chaining.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from app.database.base import Base


class Evidence(Base):
    __tablename__ = "evidence_ledger"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(64), unique=True, index=True, nullable=False) # e.g. "EVD-20260903-8821"
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    
    file_name = Column(String(255), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)
    mime_type = Column(String(64), default="message/rfc822", nullable=False)
    
    # Cryptographic Proof (Off-Chain Immutable Chain)
    sha256_hash = Column(String(64), index=True, nullable=False)
    previous_hash = Column(String(64), default="0" * 64, nullable=False) # Genesis is zeros
    ledger_index = Column(Integer, unique=True, index=True, nullable=False)
    
    uploaded_by = Column(String(64), default="SYSTEM_ANALYST", nullable=False)
    captured_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Optional testnet anchor reference (Phase 4/5)
    polygon_amoy_tx_hash = Column(String(66), nullable=True)

    # Relationships
    case = relationship("Case", back_populates="evidence_items")
