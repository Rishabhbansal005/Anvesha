export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type OriginConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNRELIABLE';
export type ThreatType = 'BEC' | 'CREDENTIAL_PHISHING' | 'MALWARE_DELIVERY' | 'SPOOFING_IMPERSONATION' | 'FINANCIAL_EXTORTION' | 'SPAM_BENIGN';
export type CaseStatus = 
  | 'NEW' 
  | 'TRIAGED' 
  | 'INVESTIGATING' 
  | 'ESCALATED' 
  | 'RESOLVED' 
  | 'CLOSED' 
  | 'IN_PROGRESS' 
  | 'UNDER_REVIEW' 
  | 'FALSE_POSITIVE';

export type AnalystDecisionType = 
  | 'CONFIRMED_THREAT' 
  | 'BENIGN_FALSE_POSITIVE' 
  | 'NEEDS_MORE_EVIDENCE' 
  | 'PENDING';

export type ActivityEventType = 
  | 'STATUS_CHANGE' 
  | 'ASSIGNMENT_CHANGE' 
  | 'ANALYST_DECISION' 
  | 'NOTE_ADDED' 
  | 'CASE_ESCALATED' 
  | 'CASE_RESOLVED' 
  | 'CASE_CLOSED' 
  | 'CASE_REOPENED' 
  | 'SYSTEM_ALERT';

export interface CaseNoteItem {
  id: string;
  case_id: string;
  author_id: string;
  author_email?: string | null;
  content: string;
  created_at: string;
}

export interface CaseActivityItem {
  id: string;
  case_id: string;
  event_type: ActivityEventType;
  actor_id: string;
  actor_email?: string | null;
  description: string;
  details?: Record<string, any>;
  created_at: string;
}

export interface CaseItem {
  id: number | string;
  case_number: string;
  title: string;
  description?: string;
  risk_score: number;
  risk_level: RiskLevel;
  threat_type: ThreatType;
  status: CaseStatus;
  probable_origin_ip?: string;
  origin_confidence: OriginConfidence;
  approximate_location?: string;
  assigned_to?: string | number | null;
  campaign_id?: number | string | null;
  analyst_decision?: AnalystDecisionType | null;
  analyst_decision_reason?: string | null;
  analyst_decision_at?: string | null;
  analyst_decision_by?: string | null;
  escalation_reason?: string | null;
  created_at: string;
  updated_at: string;
  details?: {
    sender_display?: string;
    sender_address?: string;
    reply_to?: string;
    return_path?: string;
    spf_result?: string;
    dkim_result?: string;
    dmarc_result?: string;
    hop_count?: number;
    delivery_path?: Array<{
      hop: number;
      relay: string;
      auth: string;
      latency: string;
      location: string;
    }>;
    flagged_indicators?: string[];
    evidence_id?: string;
    sha256_hash?: string;
  };
}

export interface AlertItem {
  id: number;
  case_id: number;
  case_number: string;
  title: string;
  summary: string;
  risk_score: number;
  risk_level: RiskLevel;
  threat_type: ThreatType;
  is_reviewed: boolean;
  is_escalated: boolean;
  created_at: string;
}

export interface CampaignItem {
  id: number;
  name: string;
  threat_cluster?: string;
  threat_type: string;
  description?: string;
  severity: string;
  confidence_score: number;
  associated_cases: string[];
  shared_iocs: string[];
  is_active: boolean;
  first_seen: string;
  last_seen: string;
}

export interface EvidenceRecord {
  id: number;
  evidence_id: string;
  case_id: number;
  case_number: string;
  file_name: string;
  file_size_bytes: number;
  mime_type: string;
  sha256_hash: string;
  previous_hash: string;
  ledger_index: number;
  uploaded_by: string;
  captured_at: string;
  chain_status: string;
}

export interface DashboardStats {
  total_emails_analyzed: number;
  active_threat_level: string;
  threat_trend_percentage: number;
  threat_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  unreviewed_alerts_count: number;
  critical_cases_count: number;
  urgent_actions_required: Array<{
    case_number: string;
    title: string;
    risk_score: number;
    risk_level: string;
    reason: string;
    time_received: string;
  }>;
  active_campaigns_count: number;
  correlated_iocs_count: number;
  primary_observed_asns: string[];
  recent_activity: Array<{
    id: string;
    timestamp: string;
    type: string;
    description: string;
    severity: string;
  }>;
  is_simulated_data: boolean;
  system_status: string;
}

export type FieldStatus = 'OBSERVED' | 'ENRICHED' | 'UNAVAILABLE' | 'NO_DATA' | 'ERROR';

export interface AttributionAssessment {
  threat_risk: string;
  threat_score?: number;
  observed_infrastructure: string;
  origin_confidence: string;
  actor_identity: string;
  attribution_boundary: string;
  reason: string;
  evidence_nature?: string;
  created_at: string;
}

export interface EvidenceGapItem {
  item: string;
  status: string;
  verified: boolean;
}

export interface AdditionalEvidenceOption {
  evidence_type: string;
  source: string;
  utility: string;
}

export interface EvidenceGapData {
  current_evidence: EvidenceGapItem[];
  identified_gaps: string[];
  additional_evidence_options: AdditionalEvidenceOption[];
  recommended_next_action: string;
  created_at?: string;
}

export interface InfrastructureData {
  ip_address?: string;
  ip_version?: number;
  is_private?: boolean;
  route_type?: string;
  country?: string;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  geoip_coordinates_status?: string;
  geoip_coordinates_reason?: string;
  asn?: string;
  isp?: string;
  organization?: string;
  hosting_provider?: string;
  cloud_classification?: string;
  classification_source?: string;
  vpn_tor_proxy_indicator?: string;
  tor_vpn_observation?: string;
  status?: string;
  reputation_score?: number | null;
  threat_tags?: string[];
  confidence?: string;
  evidence_nature?: string;
  disclaimer?: string;
  lookup_timestamp?: string;
  threat_intelligence?: any;
  dns_records?: any;
  rdap?: any;
}

export interface CategoryScoreItem {
  score: number;
  max: number;
}

export interface CategoryScores {
  ml_risk?: CategoryScoreItem;
  forensic_auth_risk?: CategoryScoreItem;
  infrastructure_risk?: CategoryScoreItem;
  behavior_bec_risk?: CategoryScoreItem;
  lookalike_impersonation_risk?: CategoryScoreItem;
  identity_impersonation_risk?: CategoryScoreItem;
}

export interface IdentitySignal {
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  points: number;
  description: string;
}

export interface IdentityImpersonationEvidence {
  model: string;
  identity_impersonation_detected: boolean;
  identity_impersonation_score: number;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';
  observed_identity: string;
  observed_sender: string;
  observed_local_part?: string;
  observed_domain?: string;
  reply_to?: string | null;
  trusted_identity?: string | null;
  signals: IdentitySignal[];
  score_breakdown?: Array<{ rule: string; points: number }>;
  authentication_context?: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
    all_pass?: boolean;
    disclaimer?: string | null;
  };
  attribution?: {
    actor_identity: string;
    attribution_boundary?: string;
  };
  disclaimer: string;
  model_status?: string;
}

export interface LookalikeEvidence {
  model: string;
  signal: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';
  raw_model_score: number;
  deterministic_indicators: string[];
  candidate_domain: string;
  trusted_domain: string;
  target_brand?: string;
  features?: {
    levenshtein_distance?: number;
    normalized_edit_distance?: number;
    jaro_winkler?: number;
    length_diff?: number;
    tld_match?: number;
    has_homoglyph?: number;
    is_punycode?: number;
    digit_substitution_count?: number;
    hyphen_count_diff?: number;
    brand_in_subdomain?: number;
  };
  explanation?: string[];
  model_status: string;
  disclaimer: string;
}

export interface MLSignalData {
  ml_score: number;
  ml_probability: number;
  ml_factors: string[];
  model_identifier?: string;
  predicted_class?: string;
  confidence?: string;
  tokens_detected?: string[];
}

export interface EvidenceContributionItem {
  category: string;
  signal: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  contribution: number;
  description: string;
  source: string;
  evidence_id: string;
  parent_evidence_id?: string | null;
  independence_group: string;
}

export interface EvidenceContradictionItem {
  type: string;
  description: string;
  conflicting_signals: string[];
  resolution_note: string;
}

export interface FusionCategoryItem {
  score: number;
  max: number;
}

export interface FusionAttributionData {
  actor_identity: string;
  observed_infrastructure?: string;
  origin_confidence?: string;
  attribution_boundary: string;
}

export interface ForensicFusionResult {
  model: string;
  fusion_score: number;
  risk_level: RiskLevel;
  fusion_confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  confidence_rationale: string[];
  primary_signals: string[];
  supporting_signals: string[];
  category_breakdown: {
    content: FusionCategoryItem;
    identity: FusionCategoryItem;
    infrastructure: FusionCategoryItem;
    authentication: FusionCategoryItem;
    threat_intel: FusionCategoryItem;
    campaign: FusionCategoryItem;
    [key: string]: FusionCategoryItem;
  };
  contributions: EvidenceContributionItem[];
  contradictions: EvidenceContradictionItem[];
  forensic_interpretation: string;
  attribution: FusionAttributionData;
  evidence_gaps?: any;
  disclaimer: string;
}
