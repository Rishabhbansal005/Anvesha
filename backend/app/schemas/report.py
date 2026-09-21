"""
Pydantic Schemas for ANVESH Forensic Report & Evidence Export (Phase 10).
Defines the canonical, structured forensic dossier data model.
Enforces 100% parity between JSON export and PDF export,
and maintains the strict non-attribution boundary invariant.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class CaseIdentification(BaseModel):
    case_id: str
    case_number: str
    case_status: str
    case_created_at: str
    report_generated_at: str
    risk_score: int
    risk_level: str
    threat_type: str
    investigator: Optional[str] = "Not assigned"
    campaign_id: Optional[str] = None


class InvestigationSummary(BaseModel):
    threat_risk: str
    risk_score: int
    primary_findings: List[str] = []
    authentication_summary: str
    attribution_summary: str = "Actor Identity: NOT ESTABLISHED"


class EvidenceIntegrity(BaseModel):
    evidence_id: str
    original_filename: str = "submitted_email.eml"
    sha256_hash: str
    original_email_sha256: Optional[str] = None
    report_sha256: Optional[str] = None
    file_size_bytes: int = 0
    ingestion_timestamp: str
    evidence_type: str = "RFC_822_ELECTRONIC_MAIL"
    preservation_status: str = "VERIFIED"

    def model_post_init(self, __context: Any) -> None:
        if not self.original_email_sha256:
            self.original_email_sha256 = self.sha256_hash


class OriginalEmailMetadata(BaseModel):
    from_header: str
    to_header: str
    cc_header: Optional[str] = None
    reply_to_header: Optional[str] = None
    return_path_header: Optional[str] = None
    subject_header: str
    date_header: Optional[str] = None
    message_id_header: str
    mime_version: Optional[str] = "1.0"

    @property
    def sender(self) -> str:
        return self.from_header

    @property
    def recipient(self) -> str:
        return self.to_header

    @property
    def subject(self) -> str:
        return self.subject_header


class RelayHop(BaseModel):
    hop: int
    raw: str
    ips: List[str] = []
    ip: Optional[str] = None
    is_public: bool = False
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    timezone: Optional[str] = None


class HeaderTransportAnalysis(BaseModel):
    total_hops: int
    earliest_observable_public_ip: Optional[str] = None
    origin_confidence: str
    relay_chain: List[RelayHop] = []
    anomalies: List[str] = []


class AuthenticationAnalysis(BaseModel):
    spf_status: str
    dkim_status: str
    dmarc_status: str
    auth_matrix_verdict: str
    mandatory_protocol_interpretation: str = (
        "Authentication confirms that the message passed the relevant domain authentication "
        "checks. This does not establish that the sender account was operated by the legitimate account owner."
    )


class OriginInfrastructure(BaseModel):
    probable_origin_ip: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    hosting_provider: Optional[str] = None
    cloud_classification: Optional[str] = None
    vpn_tor_proxy_indicator: str = "NONE"
    dns_records: Optional[Dict[str, Any]] = None
    rdap: Optional[Dict[str, Any]] = None


class ThreatIntelligenceFinding(BaseModel):
    source: str
    indicator: str
    result: str
    severity: str
    reputation_score: Optional[int] = None
    timestamp: Optional[str] = None
    provenance: Optional[str] = None


class Model1PhishingEvidence(BaseModel):
    model: str = "anvesh_phishing_baseline"
    model_name: str = "Model 1 Phishing Text Baseline"
    model_version: str = "1.0.0"
    artifact_hash: str = "f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7"
    ml_score: int = 0
    ml_probability: float = 0.0
    confidence_score: float = 0.0
    factors: List[str] = []
    status: str = "FROZEN"

    def model_post_init(self, __context: Any) -> None:
        if not self.confidence_score and self.ml_probability:
            self.confidence_score = self.ml_probability


class Model2BECEvidence(BaseModel):
    model: str = "bec_baseline_v1"
    model_name: str = "Model 2 BEC Baseline"
    model_version: str = "1.0.0"
    artifact_hash: str = "afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8"
    behavior_score: int = 0
    confidence_score: float = 0.0
    bec_keywords: List[str] = []
    status: str = "FROZEN"

    def model_post_init(self, __context: Any) -> None:
        if not self.confidence_score:
            self.confidence_score = round(min(self.behavior_score / 20.0, 1.0), 2)


class Model3AIdentityEvidence(BaseModel):
    model: str = "model3a_deterministic_v1"
    model_name: str = "Model 3A Identity Impersonation Baseline"
    model_type: str = "Governed Deterministic Baseline"
    signal_type: str = "Identity Impersonation Signal"
    identity_impersonation_score: int = 0
    confidence: str = "NONE"
    observed_identity: str = "Unknown"
    observed_sender: str = "Unknown"
    trusted_identity: Optional[str] = None
    reply_to_mismatch: Optional[str] = None
    signals: List[Dict[str, Any]] = []
    actor_identity: str = "Actor Identity: NOT ESTABLISHED"
    actor_attribution: str = "Actor Identity: NOT ESTABLISHED"


class Model3BLookalikeEvidence(BaseModel):
    model: str = "lookalike_domain_v1"
    model_name: str = "Model 3B Lookalike Domain Baseline"
    model_version: str = "1.0.0"
    artifact_hash: str = "31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559"
    signal: str = "NONE"
    candidate_domain: str = ""
    trusted_domain: str = ""
    raw_model_score: float = 0.0
    deterministic_indicators: List[str] = []
    status: str = "FROZEN"


class DetectionEvidence(BaseModel):
    model_1_phishing: Optional[Model1PhishingEvidence] = None
    model_2_bec: Optional[Model2BECEvidence] = None
    model_3a_identity: Optional[Model3AIdentityEvidence] = None
    model_3b_lookalike: Optional[Model3BLookalikeEvidence] = None


class CampaignCorrelationData(BaseModel):
    campaign_id: Optional[str] = None
    name: Optional[str] = None
    campaign_name: Optional[str] = None
    status: Optional[str] = None
    confidence: Optional[str] = None
    confidence_score: Optional[int] = None
    case_count: int = 1
    shared_observables: List[str] = []
    matched_indicators: List[str] = []
    explanation: Optional[str] = "No campaign correlation established."

    def model_post_init(self, __context: Any) -> None:
        if not self.campaign_name and self.name:
            self.campaign_name = self.name
        if not self.matched_indicators and self.shared_observables:
            self.matched_indicators = self.shared_observables


class FusionCategoryScore(BaseModel):
    score: int
    max: int


class ForensicSignalFusionReportData(BaseModel):
    model: str = "anvesh_forensic_fusion_v1"
    fusion_score: int
    risk_level: str
    fusion_confidence: str
    confidence_rationale: List[str] = []
    primary_signals: List[str] = []
    supporting_signals: List[str] = []
    category_breakdown: Dict[str, FusionCategoryScore]
    forensic_interpretation: str


class EvidenceContradictionReportItem(BaseModel):
    type: str
    description: str
    conflicting_signals: List[str]
    resolution_note: str


class AttributionReportAssessment(BaseModel):
    actor_identity: str = "NOT ESTABLISHED"
    origin_confidence: str
    observed_infrastructure: str
    evidence_boundary: str = (
        "The available email and infrastructure evidence establishes observable technical "
        "indicators but is insufficient to attribute the activity to a specific person."
    )


class EvidenceGapReportData(BaseModel):
    current_evidence: List[Dict[str, Any]] = []
    identified_gaps: List[str] = []
    additional_evidence_options: List[Dict[str, Any]] = []
    recommended_next_action: str


class EmailProviderIntelligenceReportData(BaseModel):
    sender_domain: str
    classification: str
    provider: Optional[str] = "UNKNOWN"
    confidence: str = "HIGH"
    source: str
    dataset_version: str
    dataset_sha256: str
    observed_at: str
    evidence: str
    risk_contribution: int = 0


class ChainOfCustodyEvent(BaseModel):
    event_id: str
    case_id: str
    evidence_id: Optional[str] = None
    event_type: str
    timestamp: str
    actor: str = "SYSTEM"
    action: Optional[str] = None
    analyst: Optional[str] = None
    description: str
    previous_event_id: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.action:
            self.action = self.event_type
        if not self.analyst:
            self.analyst = self.actor


class ForensicDossier(BaseModel):
    report_title: str = "ANVESH FORENSIC INVESTIGATION DOSSIER"
    report_id: str
    case_id: str
    report_version: str = "1.0"
    generated_at: str
    anvesh_version: str = "2.0.0-workspace"
    report_sha256: Optional[str] = None
    
    # 17 Standard Forensic Sections
    case_identification: CaseIdentification
    investigation_summary: InvestigationSummary
    evidence_integrity: EvidenceIntegrity
    email_metadata: OriginalEmailMetadata
    transport_analysis: HeaderTransportAnalysis
    authentication_analysis: AuthenticationAnalysis
    origin_infrastructure: OriginInfrastructure
    threat_intelligence: List[ThreatIntelligenceFinding] = []
    detection_evidence: DetectionEvidence
    campaign_correlation: Optional[CampaignCorrelationData] = None
    forensic_fusion: ForensicSignalFusionReportData
    contradictions: List[EvidenceContradictionReportItem] = []
    attribution_assessment: AttributionReportAssessment
    evidence_gaps: EvidenceGapReportData
    recommended_next_step: str
    chain_of_custody: List[ChainOfCustodyEvent] = []
    email_provider_intelligence: Optional[EmailProviderIntelligenceReportData] = None
    limitations: List[str] = [
        "Email headers can be incomplete, forged, or manipulated prior to ingestion.",
        "IP geolocation represents an IP-associated infrastructure location, not a physical person's location.",
        "Authentication validation confirms protocol authorization only, not human identity or mailbox non-compromise.",
        "Cloud, VPN, and TOR infrastructure can obscure true origin trajectory.",
        "Campaign correlation establishes observable clustering, not common legal authorship or actor identity.",
        "Technical observables are insufficient for legal attribution; physical actor identity remains NOT ESTABLISHED."
    ]
    disclaimer: str = (
        "ANVESH Forensic Investigation Dossier synthesizes technical observables, cryptographic checks, "
        "and machine learning signals only. It does not establish attacker identity, legal liability, or criminal intent."
    )

    @property
    def version(self) -> str:
        v = str(self.report_version)
        return f"v{v}" if not v.startswith("v") else v

    @property
    def ml_models(self) -> DetectionEvidence:
        return self.detection_evidence

    @property
    def attribution(self) -> AttributionReportAssessment:
        return self.attribution_assessment

    @property
    def executive_summary(self) -> InvestigationSummary:
        return self.investigation_summary

    @property
    def final_assessment(self) -> str:
        return self.investigation_summary.high_level_narrative

    @property
    def observables(self) -> List[ThreatIntelligenceFinding]:
        return self.threat_intelligence

    @property
    def case_metadata(self) -> CaseIdentification:
        return self.case_identification

    @property
    def authentication_matrix(self) -> AuthenticationAnalysis:
        return self.authentication_analysis

    @property
    def network_origin(self) -> OriginInfrastructure:
        return self.origin_infrastructure
