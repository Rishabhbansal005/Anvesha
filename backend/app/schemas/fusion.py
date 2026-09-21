"""
Pydantic Schemas for ANVESH Forensic Signal Fusion (Phase 9B).
Enforces explainable cross-modal evidence synthesis, anti-double-counting,
and mandatory non-attribution boundaries.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class EvidenceContribution(BaseModel):
    category: str = Field(..., description="CONTENT, IDENTITY, INFRASTRUCTURE, AUTHENTICATION, THREAT_INTEL, CAMPAIGN")
    signal: str = Field(..., description="Unique technical signal name")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    contribution: int = Field(..., description="Integer score contribution within category cap")
    description: str = Field(..., description="Human-readable explanation of the finding")
    source: str = Field(..., description="Originating engine: MODEL_1, MODEL_2, MODEL_3A, MODEL_3B, SPF_VERIFIER, IP_INTEL, etc.")
    evidence_id: str = Field(..., description="Unique immutable evidence identifier")
    parent_evidence_id: Optional[str] = Field(None, description="Parent evidence ID if derived or correlated")
    independence_group: str = Field(..., description="Group key used to prevent double-counting across overlapping observables")


class EvidenceContradiction(BaseModel):
    type: str = Field(..., description="CONTRADICTION_TYPE: AUTH_PASS_BUT_IDENTITY_SUSPICIOUS, MALICIOUS_IP_BENIGN_CONTENT, etc.")
    description: str = Field(..., description="Summary of the conflicting evidence")
    conflicting_signals: List[str] = Field(..., description="Signals that exhibit tension or contradiction")
    resolution_note: str = Field(..., description="Forensic guidance on resolving the tension (e.g. compromised account invariant)")


class CategoryBreakdownItem(BaseModel):
    score: int
    max: int


class FusionAttribution(BaseModel):
    actor_identity: str = "NOT ESTABLISHED"
    observed_infrastructure: Optional[str] = None
    origin_confidence: Optional[str] = None
    attribution_boundary: str = "Technical headers and forensic signal fusion establish transport trajectory, identity discrepancy, and infrastructure indicators only. Physical identity of the threat actor is NOT ESTABLISHED."


class ForensicFusionRequest(BaseModel):
    ml_signal: Optional[Dict[str, Any]] = None
    behavior_signal: Optional[Dict[str, Any]] = None
    identity_impersonation: Optional[Dict[str, Any]] = None
    lookalike_evidence: Optional[Dict[str, Any]] = None
    auth_context: Optional[Dict[str, Any]] = None
    transport_evidence: Optional[Dict[str, Any]] = None
    threat_intel: Optional[Dict[str, Any]] = None
    campaign: Optional[Dict[str, Any]] = None
    evidence_gaps: Optional[Dict[str, Any]] = None
    disposable_evidence: Optional[Dict[str, Any]] = None


class ForensicFusionResult(BaseModel):
    model: str = "anvesh_forensic_fusion_v1"
    fusion_score: int = Field(..., ge=0, le=100, description="Explainable synthesized forensic risk score (0-100)")
    risk_level: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    fusion_confidence: str = Field(..., description="HIGH, MEDIUM, LOW based on evidence completeness and independence")
    confidence_rationale: List[str] = []
    primary_signals: List[str] = Field(..., description="Top deterministic or high-severity indicators")
    supporting_signals: List[str] = Field(..., description="Corroborating contextual or behavioral clues")
    category_breakdown: Dict[str, CategoryBreakdownItem] = Field(..., description="Score breakdown across 6 capped categories")
    contributions: List[EvidenceContribution] = Field(..., description="Detailed list of all non-double-counted evidence contributions")
    contradictions: List[EvidenceContradiction] = Field(default=[], description="Explicitly surfaced contradictory evidence")
    forensic_interpretation: str = Field(..., description="Analyst-ready deterministic synthesis conclusion")
    attribution: FusionAttribution = Field(default_factory=FusionAttribution)
    evidence_gaps: Optional[Dict[str, Any]] = None
    disclaimer: str = "Forensic Signal Fusion synthesizes technical observables and model evidence only. It does not establish attacker identity, legal liability, or actor intent."
