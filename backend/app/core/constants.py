"""
Forensic constants, risk levels, and operational statuses for PROJECT_NAME.
"""
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"          # 85 - 100
    HIGH = "HIGH"                  # 70 - 84
    MEDIUM = "MEDIUM"              # 40 - 69
    LOW = "LOW"                    # 15 - 39
    INFORMATIONAL = "INFORMATIONAL"# 0 - 14


def get_risk_level_from_score(score: int) -> RiskLevel:
    """Derives normalized risk level from 0-100 integer score."""
    if score >= 85:
        return RiskLevel.CRITICAL
    elif score >= 70:
        return RiskLevel.HIGH
    elif score >= 40:
        return RiskLevel.MEDIUM
    elif score >= 15:
        return RiskLevel.LOW
    return RiskLevel.INFORMATIONAL


class OriginConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNRELIABLE = "UNRELIABLE"


class CaseStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    # Legacy backward-compatibility aliases
    IN_PROGRESS = "IN_PROGRESS"
    UNDER_REVIEW = "UNDER_REVIEW"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AnalystDecisionType(str, Enum):
    CONFIRMED_THREAT = "CONFIRMED_THREAT"
    BENIGN_FALSE_POSITIVE = "BENIGN_FALSE_POSITIVE"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"


class ActivityEventType(str, Enum):
    CASE_CREATED = "CASE_CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    CASE_ASSIGNED = "CASE_ASSIGNED"
    CASE_REASSIGNED = "CASE_REASSIGNED"
    CASE_UNASSIGNED = "CASE_UNASSIGNED"
    NOTE_ADDED = "NOTE_ADDED"
    DECISION_RECORDED = "DECISION_RECORDED"
    CASE_ESCALATED = "CASE_ESCALATED"
    CASE_RESOLVED = "CASE_RESOLVED"
    CASE_CLOSED = "CASE_CLOSED"
    CASE_REOPENED = "CASE_REOPENED"
    EVIDENCE_INGESTED = "EVIDENCE_INGESTED"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    REPORT_GENERATED = "REPORT_GENERATED"


ALLOWED_STATUS_TRANSITIONS = {
    CaseStatus.NEW: [CaseStatus.TRIAGED, CaseStatus.INVESTIGATING, CaseStatus.RESOLVED],
    CaseStatus.TRIAGED: [CaseStatus.INVESTIGATING, CaseStatus.ESCALATED, CaseStatus.RESOLVED],
    CaseStatus.INVESTIGATING: [CaseStatus.ESCALATED, CaseStatus.RESOLVED, CaseStatus.CLOSED],
    CaseStatus.ESCALATED: [CaseStatus.INVESTIGATING, CaseStatus.RESOLVED],
    CaseStatus.RESOLVED: [CaseStatus.CLOSED, CaseStatus.INVESTIGATING],
    CaseStatus.CLOSED: [CaseStatus.INVESTIGATING],
    # Legacy compatibility mappings
    CaseStatus.IN_PROGRESS: [CaseStatus.INVESTIGATING, CaseStatus.ESCALATED, CaseStatus.RESOLVED],
    CaseStatus.UNDER_REVIEW: [CaseStatus.INVESTIGATING, CaseStatus.ESCALATED, CaseStatus.RESOLVED],
    CaseStatus.FALSE_POSITIVE: [CaseStatus.CLOSED, CaseStatus.RESOLVED],
}


class ThreatType(str, Enum):
    BEC = "BEC"
    CREDENTIAL_PHISHING = "CREDENTIAL_PHISHING"
    MALWARE_DELIVERY = "MALWARE_DELIVERY"
    SPOOFING_IMPERSONATION = "SPOOFING_IMPERSONATION"
    FINANCIAL_EXTORTION = "FINANCIAL_EXTORTION"
    SPAM_BENIGN = "SPAM_BENIGN"


class IOCType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"
    INTELLIGENCE_OBSERVATION = "INTELLIGENCE_OBSERVATION"


class AuthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NONE = "NONE"
    NEUTRAL = "NEUTRAL"


class EmailDomainClassification(str, Enum):
    NORMAL = "NORMAL"
    DISPOSABLE = "DISPOSABLE"
    FORWARDING_PRIVACY = "FORWARDING_PRIVACY"
    UNKNOWN = "UNKNOWN"
