"""
ANVESH Intelligence Base Interfaces & Standardized Result Schemas.
Enforces the Strict Zero-Fabrication Contract and Evidence Provenance Tracking:
- Explicit statuses: OBSERVED, ENRICHED, UNAVAILABLE, NO_DATA, ERROR.
- Strict separation of OBSERVED vs DERIVED evidence nature.
- Disclaimers on infrastructure vs attacker physical location.
"""
from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class IntelligenceStatus(str, Enum):
    OBSERVED = "OBSERVED"
    ENRICHED = "ENRICHED"
    UNAVAILABLE = "UNAVAILABLE"
    NO_DATA = "NO_DATA"
    ERROR = "ERROR"


class EvidenceNature(str, Enum):
    OBSERVED = "OBSERVED"  # Directly witnessed in immutable transport headers
    DERIVED = "DERIVED"    # Retrieved from external query or computed inference


class OriginConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNDETERMINED = "UNDETERMINED"


class ThreatVerdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class BaseEnrichmentResult(BaseModel):
    indicator: str
    indicator_type: str
    status: IntelligenceStatus
    provider: str
    source: str
    evidence_nature: EvidenceNature = EvidenceNature.DERIVED
    lookup_timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    confidence: str = "MEDIUM"
    disclaimer: str = "IP-associated infrastructure location. Does not establish physical actor location."
    data: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


class BaseIntelligenceProvider:
    """Abstract base for all external or local intelligence providers."""
    def __init__(self, name: str):
        self.name = name

    def is_configured(self) -> bool:
        """Returns True only if valid API keys/endpoints are configured."""
        return True

    def get_unconfigured_result(self, indicator: str, indicator_type: str, reason: str) -> BaseEnrichmentResult:
        return BaseEnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            status=IntelligenceStatus.UNAVAILABLE,
            provider=self.name,
            source=f"{self.name}_PROVIDER",
            evidence_nature=EvidenceNature.DERIVED,
            confidence="NONE",
            disclaimer=f"Provider {self.name} is not configured in this environment.",
            data={},
            error_message=reason
        )

    def get_error_result(self, indicator: str, indicator_type: str, error_msg: str) -> BaseEnrichmentResult:
        return BaseEnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            status=IntelligenceStatus.ERROR,
            provider=self.name,
            source=f"{self.name}_PROVIDER",
            evidence_nature=EvidenceNature.DERIVED,
            confidence="NONE",
            disclaimer="Provider request failed or timed out.",
            data={},
            error_message=error_msg
        )

    def get_no_data_result(self, indicator: str, indicator_type: str, reason: str = "No records found") -> BaseEnrichmentResult:
        return BaseEnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            status=IntelligenceStatus.NO_DATA,
            provider=self.name,
            source=f"{self.name}_PROVIDER",
            evidence_nature=EvidenceNature.DERIVED,
            confidence="NONE",
            disclaimer="Authoritative source returned no matching records for this indicator.",
            data={},
            error_message=reason
        )
