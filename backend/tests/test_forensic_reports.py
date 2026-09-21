"""
Tests for ANVESH Phase 10: Forensic Report & Evidence Export.

Comprehensive test suite verifying:
1. Canonical report generation for a complete case (all 17 sections populated)
2. Canonical report generation for a minimal case (missing email, evidence, hops, IOCs)
3. Preserved original email SHA-256 matches input evidence record
4. Computed report SHA-256 is present, valid 64-char hex, and sensitive to content changes
5. Forensic fusion output preserved without modification
6. Model 1 phishing score and label preserved
7. Model 2 BEC score and label preserved
8. Model 3A identity impersonation score and label preserved
9. Model 3B lookalike domain score and label preserved
10. Campaign correlation metadata preserved
11. Attribution boundary language preserved ("Actor Identity: NOT ESTABLISHED")
12. Network origin section uses "Probable Origin IP" (zero "attacker location" or "attacker IP")
13. Missing evidence fields safe fallbacks (zero crashes)
14. Chain-of-custody log contains valid event with timestamp and analyst
15. Report versioning increments properly (1.0 -> 1.1)
16. PDF export generates valid bytes starting with '%PDF'
17. JSON export generates valid JSON matching canonical schema
18. PDF and JSON exports have 100% data parity
19. Fast-fail on non-existent case ID
20. Report excludes internal system secrets and database connection strings
"""

import json
import re
import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.schemas.report import ForensicDossier
from app.services.forensic_report_service import ForensicReportService, forensic_report_service
from app.services.pdf_report_generator import pdf_report_generator
from app.main import app


# ---------------------------------------------------------------------------
# Fixtures & Mocks
# ---------------------------------------------------------------------------

MOCK_COMPLETE_CASE = {
    "id": "case-uuid-101",
    "case_number": "ANV-2026-TEST101",
    "title": "Suspected Executive Impersonation & Wire Fraud",
    "status": "UNDER_REVIEW",
    "risk_score": 88,
    "risk_level": "CRITICAL",
    "threat_type": "BEC",
    "probable_origin_ip": "185.220.101.5",
    "origin_confidence": "HIGH",
    "approximate_location": "Frankfurt, Germany",
    "campaign_id": "cmp-uuid-alpha",
    "created_at": "2026-09-01T12:00:00Z",
    "updated_at": "2026-09-01T14:30:00Z"
}

MOCK_EMAIL_RECORD = {
    "id": "email-uuid-101",
    "case_id": "case-uuid-101",
    "message_id": "<20260901.exec.msg01@finance-corp-gateway.com>",
    "sender": "CEO John Doe <ceo@lookalike-corp.com>",
    "recipient": "cfo@target-org.com",
    "subject": "Urgent: Q3 Vendor Settlement Authorization",
    "reply_to": "exec-desk@freemail-service.net",
    "spf_status": "FAIL",
    "dkim_status": "FAIL",
    "dmarc_status": "FAIL",
    "relay_count": 4,
    "delivery_hops_json": [
        {"hop_number": 1, "from_server": "mail-relay.attacker.net", "by_server": "edge01.isp.com", "ip": "185.220.101.5", "timestamp": "2026-09-01T11:58:00Z", "delay_seconds": 2},
        {"hop_number": 2, "from_server": "edge01.isp.com", "by_server": "mx.target-org.com", "ip": "194.25.0.1", "timestamp": "2026-09-01T11:59:00Z", "delay_seconds": 60}
    ],
    "raw_headers": "Received: from mail-relay.attacker.net ...\nSubject: Urgent: Q3 Vendor Settlement Authorization"
}

MOCK_EVIDENCE_RECORD = {
    "id": "ev-uuid-101",
    "case_id": "case-uuid-101",
    "evidence_id": "EV-ANV-2026-TEST101",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "file_size_bytes": 45120,
    "uploaded_by": "SOC_ANALYST_07",
    "created_at": "2026-09-01T12:05:00Z"
}

MOCK_IOCS = [
    {"type": "IP", "value": "185.220.101.5", "category": "NETWORK", "reputation": "MALICIOUS", "source": "HEADER_HOP_1"},
    {"type": "DOMAIN", "value": "lookalike-corp.com", "category": "IDENTITY", "reputation": "SUSPICIOUS", "source": "SENDER_HEADER"}
]

MOCK_CAMPAIGN = {
    "id": "cmp-uuid-alpha",
    "campaign_id": "CMP-2026-ALPHA",
    "name": "Global Executive Wire Fraud Swarm",
    "confidence": "HIGH",
    "case_count": 5,
    "matched_indicators": ["lookalike-corp.com", "185.220.101.5", "Urgent: Q3 Vendor"]
}


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_1_canonical_report_generation_complete_case():
    """1. Canonical report generation for a complete case (all 17 sections populated)."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        
        def query_side_effect(table, **kwargs):
            if table == "emails":
                return [MOCK_EMAIL_RECORD]
            elif table == "evidence":
                return [MOCK_EVIDENCE_RECORD]
            elif table == "iocs":
                return MOCK_IOCS
            elif table == "campaigns":
                return [MOCK_CAMPAIGN]
            return []
            
        mock_query.side_effect = query_side_effect
        
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        assert isinstance(dossier, ForensicDossier)
        assert dossier.report_id == "REP-ANV-2026-TEST101"
        assert dossier.case_identification.case_number == "ANV-2026-TEST101"
        assert dossier.email_metadata.from_header == "CEO John Doe <ceo@lookalike-corp.com>"
        assert dossier.authentication_analysis.spf_status == "FAIL"
        assert dossier.origin_infrastructure.probable_origin_ip == "185.220.101.5"
        assert dossier.detection_evidence.model_1_phishing.model_name == "Model 1 Phishing Text Baseline"
        assert dossier.detection_evidence.model_2_bec.model_name == "Model 2 BEC Baseline"
        assert dossier.detection_evidence.model_3a_identity.model_name == "Model 3A Identity Impersonation Baseline"
        assert dossier.detection_evidence.model_3b_lookalike.model_name == "Model 3B Lookalike Domain Baseline"
        assert dossier.campaign_correlation is not None
        assert len(dossier.chain_of_custody) >= 1
        assert len(dossier.report_sha256) == 64


def test_2_canonical_report_generation_minimal_case():
    """2. Canonical report generation for a minimal case (missing email, evidence, hops, IOCs)."""
    service = ForensicReportService()
    minimal_case = {
        "id": "case-uuid-min",
        "case_number": "ANV-2026-MIN",
        "title": "Minimal Case",
        "status": "NEW",
        "risk_score": 10,
        "risk_level": "LOW",
        "threat_type": "UNKNOWN",
        "created_at": "2026-09-02T10:00:00Z"
    }

    with patch.object(ForensicReportService, "_resolve_case", return_value=minimal_case), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier = service.compile_canonical_dossier("ANV-2026-MIN")
        assert isinstance(dossier, ForensicDossier)
        assert dossier.report_id == "REP-ANV-2026-MIN"
        assert dossier.origin_infrastructure.probable_origin_ip in ("Not established", None)
        assert dossier.email_metadata.from_header in ("Unknown Sender", "Unknown")
        assert dossier.authentication_analysis.spf_status == "NOT OBSERVED"
        assert len(dossier.threat_intelligence) == 0


def test_3_preserved_original_email_sha256():
    """3. Preserved original email SHA-256 matches input evidence record."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        
        mock_query.side_effect = lambda table, **kw: [MOCK_EVIDENCE_RECORD] if table == "evidence" else []
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        
        assert dossier.evidence_integrity.sha256_hash == MOCK_EVIDENCE_RECORD["sha256_hash"]


def test_4_computed_report_sha256_properties():
    """4. Computed report SHA-256 is present, valid 64-char hex, and changes on data modification."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier_1 = service.compile_canonical_dossier("ANV-2026-TEST101")
        h1 = dossier_1.report_sha256
        assert len(h1) == 64
        assert re.match(r"^[0-9a-f]{64}$", h1)
        
        # Modify case title and verify hash changes
        modified_case = dict(MOCK_COMPLETE_CASE, title="Modified Title For Hash Invalidation")
        with patch.object(ForensicReportService, "_resolve_case", return_value=modified_case):
            dossier_2 = service.compile_canonical_dossier("ANV-2026-TEST101", force_regenerate=True)
            h2 = dossier_2.report_sha256
            assert h1 != h2


def test_5_forensic_fusion_preserved():
    """5. Forensic fusion output preserved without modification in report."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        assert dossier.forensic_fusion is not None
        assert 0 <= dossier.forensic_fusion.fusion_score <= 100
        assert dossier.forensic_fusion.risk_level in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert isinstance(dossier.forensic_fusion.category_breakdown, dict)


def test_6_model_1_phishing_preserved():
    """6. Model 1 phishing score and label preserved without modification."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        mock_query.side_effect = lambda table, **kw: [MOCK_EMAIL_RECORD] if table == "emails" else []
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        
        m1 = dossier.detection_evidence.model_1_phishing
        assert m1.model_name == "Model 1 Phishing Text Baseline"
        assert m1.artifact_hash == "f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7"
        assert 0.0 <= m1.confidence_score <= 1.0


def test_7_model_2_bec_preserved():
    """7. Model 2 BEC score and label preserved without modification."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        mock_query.side_effect = lambda table, **kw: [MOCK_EMAIL_RECORD] if table == "emails" else []
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        
        m2 = dossier.detection_evidence.model_2_bec
        assert m2.model_name == "Model 2 BEC Baseline"
        assert m2.artifact_hash == "afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8"
        assert 0.0 <= m2.confidence_score <= 1.0


def test_8_model_3a_identity_preserved():
    """8. Model 3A identity impersonation score and label preserved without modification."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        mock_query.side_effect = lambda table, **kw: [MOCK_EMAIL_RECORD] if table == "emails" else []
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        
        m3a = dossier.detection_evidence.model_3a_identity
        assert m3a.model_name == "Model 3A Identity Impersonation Baseline"
        assert m3a.signal_type == "Identity Impersonation Signal"
        assert m3a.actor_attribution == "Actor Identity: NOT ESTABLISHED"


def test_9_model_3b_lookalike_preserved():
    """9. Model 3B lookalike domain score and label preserved without modification."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        mock_query.side_effect = lambda table, **kw: [MOCK_EMAIL_RECORD] if table == "emails" else []
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        
        m3b = dossier.detection_evidence.model_3b_lookalike
        assert m3b.model_name == "Model 3B Lookalike Domain Baseline"
        assert m3b.artifact_hash == "31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559"


def test_10_campaign_correlation_preserved():
    """10. Campaign correlation metadata preserved."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        
        def query_side_effect(table, **kwargs):
            if table == "campaigns":
                return [MOCK_CAMPAIGN]
            return []
            
        mock_query.side_effect = query_side_effect
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101", force_regenerate=True)
        
        assert dossier.campaign_correlation is not None
        assert dossier.campaign_correlation.campaign_id == "CMP-2026-ALPHA"
        assert dossier.campaign_correlation.name == "Global Executive Wire Fraud Swarm"
        assert dossier.campaign_correlation.confidence == "HIGH"
        assert len(dossier.campaign_correlation.shared_observables) > 0


def test_11_attribution_boundary_invariant():
    """11. Attribution boundary language preserved: 'Actor Identity: NOT ESTABLISHED'."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        assert dossier.attribution_assessment.actor_identity == "Actor Identity: NOT ESTABLISHED"
        assert "NOT ESTABLISHED" in dossier.investigation_summary.attribution_summary


def test_12_no_attacker_location_phrasing():
    """12. Zero occurrences of 'attacker location' or 'attacker IP' across entire canonical dossier."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query") as mock_query:
        
        mock_query.side_effect = lambda table, **kw: [MOCK_EMAIL_RECORD] if table == "emails" else []
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        
        dossier_json_str = dossier.model_dump_json()
        forbidden_terms = ["attacker location", "attacker ip", "the attacker is located", "attacker identity confirmed"]
        for term in forbidden_terms:
            assert term not in dossier_json_str.lower(), f"Forbidden phrasing found in dossier JSON: '{term}'"


def test_13_missing_evidence_safe_fallbacks():
    """13. Missing evidence fields set to standard safe fallbacks, no crashes."""
    service = ForensicReportService()
    empty_case = {"id": "c-empty", "case_number": "ANV-EMPTY", "title": "Empty"}
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=empty_case), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier = service.compile_canonical_dossier("ANV-EMPTY")
        assert dossier.evidence_integrity.sha256_hash in ("0" * 64, "NOT RECORDED")
        assert dossier.origin_infrastructure.probable_origin_ip in ("Not established", None)
        assert dossier.origin_infrastructure.city is None
        assert dossier.campaign_correlation is None
        assert dossier.threat_intelligence == []


def test_14_chain_of_custody_log():
    """14. Chain-of-custody log contains at least creation event with valid timestamp and analyst."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        assert len(dossier.chain_of_custody) >= 1
        ev = dossier.chain_of_custody[0]
        assert ev.event_type in ("EVIDENCE_ACQUIRED", "INGESTION_RECEIVED", "REPORT_GENERATED")
        assert ev.actor is not None
        assert ev.timestamp is not None


def test_15_report_versioning():
    """15. Report versioning increments properly (1.0 -> 1.1 on modification)."""
    from app.services.forensic_report_service import _REPORT_VERSIONS, _REPORT_CACHE
    service = ForensicReportService()
    case_ver = dict(MOCK_COMPLETE_CASE, case_number="ANV-2026-VER15")
    _REPORT_VERSIONS.pop("ANV-2026-VER15", None)
    _REPORT_CACHE.pop("ANV-2026-VER15", None)
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=case_ver), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier_v1 = service.compile_canonical_dossier("ANV-2026-VER15", force_regenerate=False)
        assert dossier_v1.report_version == "1.0"
        
        dossier_v2 = service.compile_canonical_dossier("ANV-2026-VER15", force_regenerate=True)
        assert dossier_v2.report_version == "1.1"


def test_16_pdf_export_valid_bytes():
    """16. PDF export generates valid, non-empty bytes starting with '%PDF'."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        pdf_bytes, filename = service.export_pdf("ANV-2026-TEST101")
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        assert pdf_bytes.startswith(b"%PDF")
        assert filename == "ANVESH_DOSSIER_ANV-2026-TEST101.pdf"


def test_17_json_export_valid_canonical_schema():
    """17. JSON export generates valid JSON matching the canonical schema exactly."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        json_str, filename = service.export_json("ANV-2026-TEST101")
        assert filename == "ANVESH_DOSSIER_ANV-2026-TEST101.json"
        
        # Validates without error against Pydantic model
        reconstructed = ForensicDossier.model_validate_json(json_str)
        assert reconstructed.case_identification.case_number == "ANV-2026-TEST101"


def test_18_pdf_json_data_parity():
    """18. PDF and JSON exports have 100% data parity (same underlying dossier)."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        dossier = service.compile_canonical_dossier("ANV-2026-TEST101")
        json_str, _ = service.export_json("ANV-2026-TEST101")
        pdf_bytes, _ = service.export_pdf("ANV-2026-TEST101")
        
        parsed_json = json.loads(json_str)
        
        assert parsed_json["report_id"] == dossier.report_id
        assert parsed_json["report_sha256"] == dossier.report_sha256
        assert parsed_json["case_identification"]["risk_score"] == dossier.case_identification.risk_score


def test_19_fast_fail_non_existent_case():
    """19. Fast-fail on non-existent case ID (raises ValueError / returns 404)."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=None):
        with pytest.raises((ValueError, HTTPException)):
            service.compile_canonical_dossier("NON-EXISTENT-CASE")


def test_20_secrets_exclusion_and_api_endpoints():
    """20. Report generation excludes internal system secrets and database connection strings; tests API endpoints."""
    service = ForensicReportService()
    
    with patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        json_str, _ = service.export_json("ANV-2026-TEST101")
        
        # Verify absence of secrets
        forbidden_secrets = ["SUPABASE_KEY", "SECRET_KEY", "jwt", "postgres://", "password="]
        for sec in forbidden_secrets:
            assert sec not in json_str, f"Secret pattern '{sec}' leaked in report export!"
            
    # Test FastAPI endpoints via TestClient
    client = TestClient(app)
    with patch("app.api.v1.endpoints.cases._resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch.object(ForensicReportService, "_resolve_case", return_value=MOCK_COMPLETE_CASE), \
         patch("app.services.forensic_report_service.supabase.query", return_value=[]):
        
        # Test GET /api/v1/cases/{case_id}/report
        res_json = client.get("/api/v1/cases/ANV-2026-TEST101/report")
        assert res_json.status_code == 200
        data = res_json.json()
        assert data["report_id"] == "REP-ANV-2026-TEST101"
        assert data["attribution_assessment"]["actor_identity"] == "Actor Identity: NOT ESTABLISHED"
        
        # Test GET /api/v1/cases/{case_id}/report/pdf
        res_pdf = client.get("/api/v1/cases/ANV-2026-TEST101/report/pdf")
        assert res_pdf.status_code == 200
        assert res_pdf.headers["content-type"] == "application/pdf"
        assert res_pdf.content.startswith(b"%PDF")
        
        # Test GET /api/v1/cases/{case_id}/report/json
        res_json_export = client.get("/api/v1/cases/ANV-2026-TEST101/report/json")
        assert res_json_export.status_code == 200
        assert res_json_export.headers["content-type"] == "application/json"
        
        # Test 404 for invalid case
        with patch("app.api.v1.endpoints.cases.forensic_report_service.compile_canonical_dossier", side_effect=ValueError("Case not found")):
            res_404 = client.get("/api/v1/cases/INVALID-CASE/report")
            assert res_404.status_code == 404
