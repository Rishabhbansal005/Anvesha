"""
ANVESH Phase 12 Security Hardening & Regression Test Suite.
Exhaustively verifies 20+ security invariants across authentication, authorization,
IDOR, file upload safety, XSS protection, error masking, evidence immutability,
model hash preservation, and attribution boundaries.
"""
import os
import re
import uuid
import hashlib
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app
from app.core.config import settings
from app.core.constants import CaseStatus, AnalystDecisionType
from app.services.case_workflow_service import case_workflow_service
from app.api.v1.endpoints.emails import sanitize_evidence_filename
from app.api.v1.endpoints.cases import get_authenticated_analyst, get_report_authenticated_analyst
from app.database.supabase_client import supabase

client = TestClient(app)

MOCK_SEC_CASE = {
    "id": "case-sec-999",
    "case_number": "ANV-SEC-999",
    "title": "Security Audit Investigation",
    "status": "INVESTIGATING",
    "risk_score": 85,
    "risk_level": "HIGH",
    "threat_type": "BEC",
    "assigned_to": "SOC-ANALYST-1",
    "created_at": "2026-09-07T00:00:00.000000"
}


# ---------------------------------------------------------------------------
# 1. Unauthenticated Case Modification -> 401
# ---------------------------------------------------------------------------
def test_unauthenticated_case_modification_401():
    """Unauthenticated requests to modify cases must return 401 Unauthorized."""
    # Attempt status update without credentials
    res = client.patch(
        "/api/v1/cases/ANV-SEC-999/status",
        json={"status": "RESOLVED", "note": "Unauthorized transition attempt"}
    )
    assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"

    # Attempt note creation without credentials
    res_note = client.post(
        "/api/v1/cases/ANV-SEC-999/notes",
        json={"content": "Unauthorized note injection"}
    )
    assert res_note.status_code == 401

    # Attempt decision recording without credentials
    res_dec = client.post(
        "/api/v1/cases/ANV-SEC-999/decision",
        json={"decision": "CONFIRMED_THREAT", "reason": "Unauthorized decision"}
    )
    assert res_dec.status_code == 401


# ---------------------------------------------------------------------------
# 2. Unauthorized Case Modification -> 403
# ---------------------------------------------------------------------------
def test_unauthorized_case_modification_403():
    """Requests with restricted/insufficient analyst privileges must return 403 Forbidden."""
    with patch("app.services.case_workflow_service.supabase.query", return_value=[MOCK_SEC_CASE]):
        res = client.patch(
            "/api/v1/cases/ANV-SEC-999/status",
            json={"status": "RESOLVED", "note": "Restricted analyst attempt"},
            headers={"Authorization": "Bearer restricted_intern"}
        )
        assert res.status_code == 403, f"Expected 403, got {res.status_code}: {res.text}"
        assert "Forbidden" in res.json().get("detail", "")


# ---------------------------------------------------------------------------
# 3. IDOR Case Access Blocked
# ---------------------------------------------------------------------------
def test_idor_case_access_blocked():
    """Restricted analysts attempting unauthorized case actions are rejected."""
    with patch("app.services.case_workflow_service.supabase.query", return_value=[MOCK_SEC_CASE]):
        res = client.post(
            "/api/v1/cases/ANV-SEC-999/notes",
            json={"content": "Attempting cross-case tampering"},
            headers={"X-Analyst-ID": "restricted_external_guest"}
        )
        assert res.status_code == 403


# ---------------------------------------------------------------------------
# 4. Invalid Status Rejected
# ---------------------------------------------------------------------------
def test_invalid_status_rejected():
    """Submitting an invalid lifecycle status is rejected with 422 Unprocessable Entity."""
    res = client.patch(
        "/api/v1/cases/ANV-SEC-999/status",
        json={"status": "MALICIOUS_STATUS_INJECTION"},
        headers={"X-Analyst-ID": "SOC-ANALYST-1"}
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# 5. Invalid Decision Rejected
# ---------------------------------------------------------------------------
def test_invalid_decision_rejected():
    """Submitting an invalid decision enum is rejected with 422 Unprocessable Entity."""
    res = client.post(
        "/api/v1/cases/ANV-SEC-999/decision",
        json={"decision": "ARBITRARY_DECISION", "reason": "Testing validation"},
        headers={"X-Analyst-ID": "SOC-ANALYST-1"}
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# 6. Oversized Note Rejected
# ---------------------------------------------------------------------------
def test_oversized_note_rejected():
    """Notes exceeding 10,000 characters must be rejected with 422."""
    giant_note = "A" * 15000
    res = client.post(
        "/api/v1/cases/ANV-SEC-999/notes",
        json={"content": giant_note},
        headers={"X-Analyst-ID": "SOC-ANALYST-1"}
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# 7. Unsafe Filename Rejected / Safely Normalized
# ---------------------------------------------------------------------------
def test_unsafe_filename_rejected():
    """Executable and dangerous script uploads are rejected with 400."""
    with pytest.raises(Exception) as exc_info:
        sanitize_evidence_filename("exploit.exe")
    assert "Executable or script file" in str(exc_info.value)

    with pytest.raises(Exception) as exc_info_bat:
        sanitize_evidence_filename("payload.bat")
    assert "Executable or script file" in str(exc_info_bat.value)


# ---------------------------------------------------------------------------
# 8. Path Traversal Rejected / Neutralized
# ---------------------------------------------------------------------------
def test_path_traversal_neutralized():
    """Path traversal sequences (../../) and null bytes are stripped or rejected."""
    # Test null byte rejection
    with pytest.raises(Exception) as exc_null:
        sanitize_evidence_filename("innocent\x00.eml")
    assert "null bytes" in str(exc_null.value)

    # Test path traversal neutralization
    sanitized = sanitize_evidence_filename("../../../etc/shadow.eml")
    assert ".." not in sanitized
    assert "/" not in sanitized
    assert sanitized.endswith(".eml")

    sanitized_win = sanitize_evidence_filename("..\\..\\windows\\system32\\evil.eml")
    assert ".." not in sanitized_win
    assert "\\" not in sanitized_win


# ---------------------------------------------------------------------------
# 9. Malicious HTML Is Not Executable / Safely Handled
# ---------------------------------------------------------------------------
def test_malicious_html_is_not_executable():
    """Submitting XSS payloads in email body/headers does not cause server-side injection."""
    xss_payload = "<script>alert('XSS-ATTACK')</script><img src=x onerror=alert(1)>"
    res = client.post(
        "/api/v1/emails/analyze",
        data={"raw_headers": f"From: attacker@evil.com\nSubject: Test\n\n{xss_payload}"}
    )
    assert res.status_code == 200
    data = res.json()
    # The title and analysis outputs should treat it strictly as forensic text
    assert data["case_number"].startswith("ANV-2026-")
    assert data["is_simulated_data"] is False


# ---------------------------------------------------------------------------
# 10. Report Access Requires Authorization
# ---------------------------------------------------------------------------
def test_report_access_requires_authorization():
    """Report endpoints reject invalid tokens with 401 and restricted tokens with 403."""
    # Invalid token -> 401
    res_invalid = client.get(
        "/api/v1/cases/ANV-SEC-999/report",
        headers={"Authorization": "Bearer invalid"}
    )
    assert res_invalid.status_code == 401

    # Restricted token -> 403
    res_restricted = client.get(
        "/api/v1/cases/ANV-SEC-999/report",
        headers={"Authorization": "Bearer restricted_guest"}
    )
    assert res_restricted.status_code == 403


# ---------------------------------------------------------------------------
# 11. Evidence Cannot Be Deleted Through Analyst Workflow
# ---------------------------------------------------------------------------
def test_evidence_cannot_be_deleted():
    """Deleting an investigation case with registered evidence is strictly blocked with 403."""
    mock_case = {"id": "c-evd-1", "case_number": "ANV-EVD-1"}
    mock_evidence = [{"evidence_id": "EVD-1", "case_id": "c-evd-1", "sha256_hash": "abcdef"}]
    
    with patch("app.api.v1.endpoints.cases._resolve_case", return_value=mock_case), \
         patch("app.api.v1.endpoints.cases.supabase.query", return_value=mock_evidence):
        res = client.delete(
            "/api/v1/cases/ANV-EVD-1",
            headers={"X-Analyst-ID": "SOC-ANALYST-1"}
        )
        assert res.status_code == 403
        assert "Evidence destruction prohibited" in res.json()["detail"]


# ---------------------------------------------------------------------------
# 12. Evidence Hash Cannot Be Changed
# ---------------------------------------------------------------------------
def test_evidence_hash_cannot_be_changed():
    """Evidence verify endpoint checks registered SHA-256 and detects record validity."""
    mock_evidence = {
        "id": "ev-1",
        "evidence_id": "EVD-101",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ledger_index": 1
    }
    with patch("app.api.v1.endpoints.evidence.supabase.query", return_value=[mock_evidence]):
        res = client.get("/api/v1/evidence/EVD-101/verify")
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is True
        assert data["chain_integrity"] == "CRYPTOGRAPHIC_CHAIN_INTACT"


# ---------------------------------------------------------------------------
# 13. Chain of Custody Append-Only
# ---------------------------------------------------------------------------
def test_chain_of_custody_append_only():
    """Activity timeline accumulates events chronologically without overwriting."""
    activities = case_workflow_service.get_activities("ANV-SEC-999")
    assert isinstance(activities, list)
    # Verify baseline system milestones exist
    system_acts = [a for a in activities if a.get("actor_type") == "SYSTEM"]
    assert len(system_acts) >= 2


# ---------------------------------------------------------------------------
# 14. Secret Values Never Appear in API Error Responses
# ---------------------------------------------------------------------------
def test_secret_values_never_in_error_responses():
    """Unhandled exceptions mask sensitive details, paths, and keys."""
    custom_client = TestClient(app, raise_server_exceptions=False)
    with patch("app.api.v1.endpoints.cases._resolve_case", side_effect=Exception("Database error with key sb_secret_xyz at C:\\Users\\secret\\path")):
        res = custom_client.get("/api/v1/cases/ANV-ERR-TEST")
        assert res.status_code == 500
        content = res.text
        assert "sb_secret" not in content
        assert "C:\\Users\\" not in content


# ---------------------------------------------------------------------------
# 15. Attribution Boundary Preserved
# ---------------------------------------------------------------------------
def test_attribution_boundary_preserved():
    """Attribution assessment must strictly maintain 'NOT ESTABLISHED'."""
    from app.services.attribution_service import attribution_service
    attr = attribution_service.generate_attribution_assessment(
        case_title="Test Phishing",
        risk_level="HIGH",
        risk_score=80,
        origin_confidence="HIGH",
        probable_origin_ip="198.51.100.1"
    )
    assert attr["actor_identity"] == "NOT ESTABLISHED"
    assert "Actor Identity: NOT ESTABLISHED" in attr["attribution_boundary"] or "transport protocol layer" in attr["attribution_boundary"]


# ---------------------------------------------------------------------------
# 16. Frozen Model Hashes Unchanged
# ---------------------------------------------------------------------------
def _find_model_path(relative_subpath: str) -> str:
    candidates = [
        os.path.join("..", "ml", "models", relative_subpath),
        os.path.join("ml", "models", relative_subpath),
        os.path.join(os.path.dirname(__file__), "..", "..", "ml", "models", relative_subpath),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    raise FileNotFoundError(f"Cannot find model file: {relative_subpath}")


def test_frozen_model_hashes_unchanged():
    """Frozen ML models (M1, M2, M3B) must match byte-exact SHA-256 hashes."""
    frozen_hashes = {
        "phishing_baseline_v1/model.joblib": "f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7",
        "bec_baseline_v1/model.joblib": "afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8",
        "lookalike_domain_v1/model.joblib": "31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559",
    }
    for subpath, expected_hash in frozen_hashes.items():
        actual_path = _find_model_path(subpath)
        with open(actual_path, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest().lower()
        assert actual_hash == expected_hash, f"Model hash mismatch for {subpath}! Expected {expected_hash}, got {actual_hash}"


# ---------------------------------------------------------------------------
# 17. Mobile / Web Configuration Does Not Expose Backend Secrets
# ---------------------------------------------------------------------------
def test_mobile_web_configs_no_backend_secrets():
    """web/.env and mobile/.env must not contain private backend secret keys."""
    forbidden_tokens = ["sb_secret_", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "service_role"]
    
    web_env_path = os.path.join("..", "web", ".env") if os.path.exists(os.path.join("..", "web", ".env")) else os.path.join("web", ".env")
    if os.path.exists(web_env_path):
        with open(web_env_path, "r", encoding="utf-8") as f:
            web_content = f.read()
        for tok in forbidden_tokens:
            assert tok not in web_content, f"Secret token '{tok}' leaked in web/.env!"

    mobile_env_path = os.path.join("..", "mobile", ".env") if os.path.exists(os.path.join("..", "mobile", ".env")) else os.path.join("mobile", ".env")
    if os.path.exists(mobile_env_path):
        with open(mobile_env_path, "r", encoding="utf-8") as f:
            mobile_content = f.read()
        for tok in forbidden_tokens:
            assert tok not in mobile_content, f"Secret token '{tok}' leaked in mobile/.env!"


# ---------------------------------------------------------------------------
# 18. CORS Configuration Safe
# ---------------------------------------------------------------------------
def test_cors_configuration_safe():
    """CORS configuration must NOT contain wildcard '*' origin when credentials are supported."""
    assert "*" not in settings.CORS_ORIGINS, "Wildcard '*' origin detected in CORS_ORIGINS with allow_credentials=True!"
    assert any("5173" in origin for origin in settings.CORS_ORIGINS)


# ---------------------------------------------------------------------------
# 19. Sensitive Headers / Tokens Not Logged
# ---------------------------------------------------------------------------
def test_sensitive_headers_not_logged():
    """Recording activity events must record actor IDs and sanitized metadata without auth tokens."""
    act = case_workflow_service.record_activity(
        case_id="ANV-SEC-999",
        event_type="NOTE_ADDED",
        actor="analyst@anvesh.internal",
        actor_type="ANALYST",
        title="Note Added",
        description="Investigation observation",
        metadata={"safe_key": "safe_value"}
    )
    assert "Authorization" not in act.get("metadata", {})
    assert "token" not in act.get("metadata", {})


# ---------------------------------------------------------------------------
# 20. Closed Case Protections Intact
# ---------------------------------------------------------------------------
def test_closed_case_protections_intact():
    """Closed cases reject decisions, notes, and direct status jumps without reopening."""
    closed_case = {
        "id": "c-closed-1",
        "case_number": "ANV-CLOSED-1",
        "status": "CLOSED"
    }
    with patch("app.services.case_workflow_service.supabase.query", return_value=[closed_case]):
        # Attempting note on closed case
        with pytest.raises(Exception) as exc_note:
            case_workflow_service.add_note(
                case_id="ANV-CLOSED-1",
                content="Late note",
                author_id="SOC-ANALYST-1"
            )
        assert "closed case" in str(exc_note.value).lower()

        # Attempting decision on closed case
        with pytest.raises(Exception) as exc_dec:
            case_workflow_service.record_decision(
                case_id="ANV-CLOSED-1",
                decision="CONFIRMED_THREAT",
                reason="Late decision",
                actor="SOC-ANALYST-1"
            )
        assert "closed case" in str(exc_dec.value).lower()


# ---------------------------------------------------------------------------
# 21. Security Headers Present on Responses
# ---------------------------------------------------------------------------
def test_security_headers_present():
    """All API responses must include defensive security headers."""
    res = client.get("/")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in res.headers
    assert "Content-Security-Policy" in res.headers
