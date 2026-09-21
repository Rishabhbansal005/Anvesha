"""
Pydantic schemas for Evidence Ledger & Cryptographic Verification.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class EvidenceRead(BaseModel):
    id: int
    evidence_id: str
    case_id: int
    file_name: str
    file_size_bytes: int
    mime_type: str
    sha256_hash: str
    previous_hash: str
    ledger_index: int
    uploaded_by: str
    captured_at: datetime
    polygon_amoy_tx_hash: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)


class EvidenceVerifyResponse(BaseModel):
    evidence_id: str
    sha256_hash: str
    is_valid: bool
    chain_integrity: str
    ledger_index: int
    verification_message: str
