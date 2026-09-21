"""
Pydantic Schemas for Forensic Attribution, Infrastructure Intelligence, and Evidence Gaps.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AttributionAssessmentResponse(BaseModel):
    case_id: str
    threat_risk: str
    threat_score: int
    observed_infrastructure: str
    origin_confidence: str
    actor_identity: str = "NOT ESTABLISHED"
    attribution_boundary: str
    reason: str
    evidence_nature: str = "DERIVED"
    created_at: str


class EvidenceItem(BaseModel):
    item: str
    status: str
    verified: bool


class AdditionalEvidenceOption(BaseModel):
    evidence_type: str
    source: str
    utility: str


class EvidenceGapResponse(BaseModel):
    case_id: str
    current_evidence: List[Dict[str, Any]]
    identified_gaps: List[str]
    additional_evidence_options: List[Dict[str, Any]]
    recommended_next_action: str
    created_at: str


class InfrastructureIntelligenceResponse(BaseModel):
    case_id: str
    ip_address: Optional[str] = None
    ip_version: int = 4
    is_private: bool = False
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = "UNAVAILABLE"
    isp: Optional[str] = "UNAVAILABLE"
    organization: Optional[str] = "UNAVAILABLE"
    hosting_provider: Optional[str] = "UNAVAILABLE"
    cloud_classification: Optional[str] = "UNAVAILABLE"
    classification_source: Optional[str] = "UNAVAILABLE"
    vpn_tor_proxy_indicator: str = "NONE"
    tor_vpn_observation: Optional[str] = None
    status: str = "OBSERVED"
    evidence_nature: str = "DERIVED"
    disclaimer: str = "IP-associated infrastructure location. Does not establish physical actor location."
    lookup_timestamp: str
    dns_records: Optional[Dict[str, Any]] = None
    rdap: Optional[Dict[str, Any]] = None
    threat_intelligence: Optional[Dict[str, Any]] = None
