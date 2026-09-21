"""
Pydantic schemas for Email analysis and parsed header models.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.core.constants import AuthStatus, RiskLevel


class EmailAnalyzeRequest(BaseModel):
    raw_content: Optional[str] = None
    file_name: Optional[str] = None


class EmailAnalyzeResponse(BaseModel):
    case_number: str
    id: Optional[str] = None
    title: Optional[str] = None
    risk_score: int
    risk_level: RiskLevel
    threat_type: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    probable_origin_ip: Optional[str] = None
    origin_confidence: str
    approximate_location: Optional[str] = None
    spf_status: AuthStatus
    dkim_status: AuthStatus
    dmarc_status: AuthStatus
    flagged_reasons: List[str]
    hops: Optional[List[Dict[str, Any]]] = None
    evidence_id: str
    sha256_hash: str
    created_at: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)
