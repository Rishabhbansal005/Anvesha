"""
Pydantic Schemas for ANVESH Model 3A (Identity & Header Impersonation Detection).
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class TrustedIdentity(BaseModel):
    identity_id: Optional[str] = None
    display_name: str
    email: str
    domain: Optional[str] = None
    identity_type: str = Field(default="EXECUTIVE", description="EXECUTIVE, SUPPLIER, FINANCE, OFFICER")
    verification_source: Optional[str] = "DIRECTORY_REGISTRY"
    verified: bool = True


class IdentitySignalItem(BaseModel):
    type: str
    severity: str
    points: int
    description: str


class ScoreBreakdownItem(BaseModel):
    rule: str
    points: int


class IdentityImpersonationRequest(BaseModel):
    sender_name: Optional[str] = None
    sender_email: Optional[str] = None
    reply_to: Optional[str] = None
    trusted_identity: Optional[TrustedIdentity] = None
    model3b_result: Optional[Dict[str, Any]] = None
    auth_context: Optional[Dict[str, str]] = None


class IdentityImpersonationResult(BaseModel):
    model: str = "model3a_deterministic_v1"
    identity_impersonation_detected: bool
    identity_impersonation_score: int
    confidence: str
    observed_identity: str
    observed_sender: str
    observed_local_part: Optional[str] = None
    observed_domain: Optional[str] = None
    reply_to: Optional[str] = None
    trusted_identity: Optional[str] = None
    signals: List[IdentitySignalItem] = []
    score_breakdown: List[ScoreBreakdownItem] = []
    authentication_context: Dict[str, Any] = {}
    attribution: Dict[str, str] = {
        "actor_identity": "NOT ESTABLISHED"
    }
    disclaimer: str
