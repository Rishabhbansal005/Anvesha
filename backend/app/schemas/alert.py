"""
Pydantic schemas for Alert entities.
"""
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.core.constants import RiskLevel, ThreatType


class AlertRead(BaseModel):
    id: int
    case_id: int
    case_number: str
    title: str
    summary: str
    risk_score: int
    risk_level: RiskLevel
    threat_type: ThreatType
    is_reviewed: bool
    is_escalated: bool
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class AlertTriageAction(BaseModel):
    action: str # "REVIEW", "ESCALATE", "NOTE"
    note: str = ""
