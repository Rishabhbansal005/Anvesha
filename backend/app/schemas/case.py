"""
Pydantic schemas for Case entities, Analyst Workflow, Decisions, Notes, and Activities.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.core.constants import (
    RiskLevel,
    CaseStatus,
    ThreatType,
    OriginConfidence,
    AnalystDecisionType,
    ActivityEventType
)


class CaseBase(BaseModel):
    title: str
    description: Optional[str] = None
    risk_score: int
    risk_level: RiskLevel
    threat_type: ThreatType
    status: CaseStatus = CaseStatus.NEW
    probable_origin_ip: Optional[str] = None
    origin_confidence: OriginConfidence = OriginConfidence.LOW
    approximate_location: Optional[str] = None


class CaseCreate(CaseBase):
    pass


class CaseStatusUpdate(BaseModel):
    status: CaseStatus
    note: Optional[str] = None


class CaseStatusTransitionRequest(BaseModel):
    status: CaseStatus
    note: Optional[str] = Field(None, max_length=1000)


class CaseAssignmentRequest(BaseModel):
    assigned_to: Optional[str] = Field(None, max_length=255, description="User ID or email to assign, or null to unassign")


class CaseDecisionRequest(BaseModel):
    decision: AnalystDecisionType
    reason: str = Field(..., min_length=3, max_length=2000, description="Mandatory investigation justification")

    @field_validator("reason")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Input contains invalid null bytes")
        return v


class CaseNoteCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000, description="Investigation note content")

    @field_validator("content")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Note content contains invalid null bytes")
        return v


class CaseNoteRead(BaseModel):
    id: str
    case_id: str
    author_id: str
    content: str
    created_at: str


class CaseEscalateRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=2000, description="Mandatory escalation reason")

    @field_validator("reason")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Escalation reason contains invalid null bytes")
        return v


class CaseResolveRequest(BaseModel):
    decision: AnalystDecisionType = Field(..., description="Mandatory analyst decision prior to resolution")
    resolution_notes: str = Field(..., min_length=3, max_length=2000, description="Resolution investigation summary")

    @field_validator("resolution_notes")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Resolution notes contain invalid null bytes")
        return v


class CaseActivityRead(BaseModel):
    id: str
    case_id: str
    event_type: str
    timestamp: str
    actor: str
    actor_type: str  # "SYSTEM" or "ANALYST"
    title: str
    description: str
    metadata: Optional[Dict[str, Any]] = None


class CaseRead(CaseBase):
    id: int
    case_number: str
    assigned_to: Optional[Any] = None
    campaign_id: Optional[int] = None
    analyst_decision: Optional[str] = None
    analyst_decision_reason: Optional[str] = None
    analyst_decision_at: Optional[str] = None
    analyst_decision_by: Optional[str] = None
    escalation_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
