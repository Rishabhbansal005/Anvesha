"""
Pydantic Schemas for Disposable and Temporary Email Intelligence (Phase 12.5).
"""
from typing import Optional
from pydantic import BaseModel, Field
from app.core.constants import EmailDomainClassification


class DisposableCheckRequest(BaseModel):
    email: Optional[str] = None
    domain: Optional[str] = None


class DisposableEmailIntel(BaseModel):
    domain: str
    classification: EmailDomainClassification
    provider_name: Optional[str] = None
    confidence: str = "HIGH"
    source: str
    source_version: str
    dataset_version: Optional[str] = None
    dataset_sha256: str
    observed_at: str
    evidence: str
    evidence_text: Optional[str] = None
    risk_contribution: int = 0
    is_disposable: bool = False
    is_privacy_relay: bool = False
    notes: Optional[str] = None

    def model_post_init(self, __context: object) -> None:
        if not self.dataset_version:
            self.dataset_version = self.source_version
        if not self.evidence_text:
            self.evidence_text = self.evidence


class DisposableDatasetMetadata(BaseModel):
    dataset_name: str
    dataset_version: str
    source: str
    license: str
    updated_at: str
    dataset_sha256: str
    total_domains: int
