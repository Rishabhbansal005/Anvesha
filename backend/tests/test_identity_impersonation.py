"""
ANVESH Phase 9A - Model 3A Identity & Header Impersonation Detection Tests.

Governance & Functional Verification:
1. TEST 1: Trusted executive display name + external freemail sender (HIGH signal)
2. TEST 2: Normal internal sender matching trusted identity (No impersonation)
3. TEST 3: From company.com + Reply-To external.com (Reply-To mismatch signal)
4. TEST 4: Display name suspicious without trusted identity (Does not assert confirmed impersonation)
5. TEST 5: SPF/DKIM/DMARC PASS + suspicious identity mismatch (Identity signal preserved)
6. TEST 6: Model 3B lookalike domain + executive display name (Combined evidence)
7. TEST 7: Compromised-account scenario (Legitimate sender + PASS; Actor Identity: NOT ESTABLISHED)
8. GOVERNANCE: Actor identity never asserted ("Actor Identity: NOT ESTABLISHED")
9. GOVERNANCE: No uncalibrated probability claims
10. GOVERNANCE: Malformed RFC-822 headers fail safely
"""

import pytest
import sys
from pathlib import Path

# Add backend and repository root to sys.path
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from ml.inference.identity_impersonation_predictor import (
    IdentityImpersonationPredictor,
    get_identity_impersonation_predictor
)
from backend.app.services.identity_impersonation_service import (
    IdentityImpersonationService,
    identity_impersonation_service
)
from backend.app.services.risk_engine import risk_engine


@pytest.fixture
def predictor():
    return IdentityImpersonationPredictor()


def test_fixture_1_executive_display_name_external_freemail(predictor):
    """TEST 1: Trusted executive display name + external sender -> HIGH impersonation signal."""
    trusted = {
        "display_name": "Anita Sharma",
        "email": "anita.sharma@company.com",
        "domain": "company.com",
        "identity_type": "EXECUTIVE"
    }
    res = predictor.predict(
        sender_header='"Anita Sharma — CFO" <anita.sharma@gmail.com>',
        trusted_identity=trusted
    )
    assert res["identity_impersonation_detected"] is True
    assert res["identity_impersonation_score"] >= 50
    assert any(s["type"] == "DISPLAY_NAME_DOMAIN_MISMATCH" for s in res["signals"])
    assert any(s["type"] == "EXECUTIVE_EXTERNAL_DOMAIN" for s in res["signals"])
    assert res["attribution"]["actor_identity"] == "NOT ESTABLISHED"


def test_fixture_2_normal_internal_sender(predictor):
    """TEST 2: Normal internal sender matching trusted identity -> No impersonation."""
    trusted = {
        "display_name": "Anita Sharma",
        "email": "anita.sharma@company.com",
        "domain": "company.com",
        "identity_type": "EXECUTIVE"
    }
    res = predictor.predict(
        sender_header='"Anita Sharma" <anita.sharma@company.com>',
        trusted_identity=trusted
    )
    assert res["identity_impersonation_detected"] is False
    assert res["identity_impersonation_score"] == 0
    assert len(res["signals"]) == 0
    assert res["attribution"]["actor_identity"] == "NOT ESTABLISHED"


def test_fixture_3_reply_to_mismatch(predictor):
    """TEST 3: From company.com + Reply-To external.com -> Reply-To mismatch signal."""
    res = predictor.predict(
        sender_header='"Finance Team" <accounts@company.com>',
        reply_to_header='wire-desk@external-escrow.net'
    )
    assert any(s["type"] == "REPLY_TO_MISMATCH" for s in res["signals"])
    assert res["identity_impersonation_score"] >= 25
    assert res["attribution"]["actor_identity"] == "NOT ESTABLISHED"


def test_fixture_4_display_name_suspicious_no_trusted_identity(predictor):
    """TEST 4: Display name suspicious but no trusted identity available -> Do NOT claim confirmed impersonation."""
    res = predictor.predict(
        sender_header='"Executive Desk" <random-user@gmail.com>',
        trusted_identity=None
    )
    # Triggers generic freemail executive indicator (+25), but does NOT claim DISPLAY_NAME_DOMAIN_MISMATCH
    assert not any(s["type"] == "DISPLAY_NAME_DOMAIN_MISMATCH" for s in res["signals"])
    assert res["trusted_identity"] is None
    assert res["attribution"]["actor_identity"] == "NOT ESTABLISHED"


def test_fixture_5_auth_pass_preserves_identity_signal(predictor):
    """TEST 5: SPF/DKIM/DMARC PASS + suspicious identity mismatch -> Identity signal remains."""
    trusted = {
        "display_name": "John Smith",
        "email": "john.smith@company.com",
        "domain": "company.com",
        "identity_type": "EXECUTIVE"
    }
    auth_ctx = {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
    res = predictor.predict(
        sender_header='"John Smith" <john.smith@gmail.com>',
        trusted_identity=trusted,
        auth_context=auth_ctx
    )
    assert res["identity_impersonation_detected"] is True
    assert res["authentication_context"]["all_pass"] is True
    # Verify compromised-account disclaimer attached
    assert "Authentication passed" in res["authentication_context"]["disclaimer"]
    assert res["attribution"]["actor_identity"] == "NOT ESTABLISHED"


def test_fixture_6_model3b_lookalike_support(predictor):
    """TEST 6: Model3B lookalike domain + executive display name -> Combined evidence."""
    trusted = {
        "display_name": "John Smith",
        "email": "john.smith@microsoft.com",
        "domain": "microsoft.com",
        "identity_type": "EXECUTIVE"
    }
    m3b_res = {
        "signal": "HIGH",
        "trusted_domain": "microsoft.com",
        "candidate_domain": "m1crosoft-support.com"
    }
    res = predictor.predict(
        sender_header='"John Smith" <support@m1crosoft-support.com>',
        trusted_identity=trusted,
        model3b_result=m3b_res
    )
    assert res["identity_impersonation_detected"] is True
    assert any(s["type"] == "MODEL3B_LOOKALIKE_SUPPORT" for s in res["signals"])
    assert any(s["type"] == "DISPLAY_NAME_DOMAIN_MISMATCH" for s in res["signals"])
    assert res["identity_impersonation_score"] >= 45


def test_fixture_7_compromised_account_scenario(predictor):
    """TEST 7: Compromised legitimate sender + PASS -> Actor Identity: NOT ESTABLISHED."""
    trusted = {
        "display_name": "Anita Sharma",
        "email": "anita.sharma@company.com",
        "domain": "company.com",
        "identity_type": "EXECUTIVE"
    }
    auth_ctx = {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
    # Sender legitimately claims Anita Sharma and matches corporate domain
    res = predictor.predict(
        sender_header='"Anita Sharma" <anita.sharma@company.com>',
        trusted_identity=trusted,
        auth_context=auth_ctx
    )
    assert res["identity_impersonation_detected"] is False
    assert res["identity_impersonation_score"] == 0
    assert res["attribution"]["actor_identity"] == "NOT ESTABLISHED"


def test_governance_invariants(predictor):
    """Governance tests for bounds, terminology, and safe degradation."""
    # 1. Zero actor claim
    res = predictor.predict(
        sender_header='"CEO Fraud" <scammer@evil.com>',
        reply_to_header='drop@bad.com',
        auth_context={"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"}
    )
    assert res["attribution"]["actor_identity"] == "NOT ESTABLISHED"
    assert "NOT ESTABLISHED" in res["attribution"]["attribution_boundary"]

    # 2. Score bounds
    assert 0 <= res["identity_impersonation_score"] <= 100
    assert "probability" not in res  # Never uncalibrated probability

    # 3. Missing / empty / malformed fields fail safely
    empty_res = predictor.predict(sender_header="")
    assert empty_res["identity_impersonation_detected"] is False
    assert empty_res["identity_impersonation_score"] == 0

    malformed_res = predictor.predict(
        sender_header="<<>>@!invalid@@broken<name",
        reply_to_header="corrupted@@@"
    )
    assert malformed_res["identity_impersonation_score"] >= 0


def test_risk_engine_isolation():
    """Verify Model 3A risk engine contribution is isolated to 0-15 points."""
    mock_identity = {
        "identity_impersonation_score": 80,
        "confidence": "HIGH",
        "observed_identity": "Anita Sharma",
        "observed_sender": "anita@gmail.com",
        "trusted_identity": "anita.sharma@company.com",
        "signals": [
            {"description": "Display name matches executive on freemail"}
        ]
    }
    risk_score, reasons = risk_engine.evaluate_identity_risk(mock_identity)
    assert 0 <= risk_score <= 15
    assert len(reasons) > 0
    assert "Actor Identity: NOT ESTABLISHED" in reasons[0]

    calc = risk_engine.calculate_risk(
        ml_score=20,
        auth_risk=10,
        infra_risk=10,
        behavior_bec_risk=10,
        lookalike_risk=10,
        identity_risk=risk_score
    )
    assert calc["category_scores"]["identity_impersonation_risk"]["score"] == risk_score
    assert calc["category_scores"]["identity_impersonation_risk"]["max"] == 15
    assert calc["risk_score"] <= 100


def test_fastapi_identity_impersonation_endpoint():
    """Verify POST /api/v1/emails/identity-impersonation-detect returns structured Model 3A result."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    payload = {
        "sender_name": "Anita Sharma — CFO",
        "sender_email": "anita.sharma@gmail.com",
        "reply_to": "wire-escrow@external-payment.net",
        "trusted_identity": {
            "display_name": "Anita Sharma",
            "email": "anita.sharma@company.com",
            "domain": "company.com",
            "identity_type": "EXECUTIVE"
        },
        "auth_context": {
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL"
        }
    }
    response = client.post("/api/v1/emails/identity-impersonation-detect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["identity_impersonation_detected"] is True
    assert data["identity_impersonation_score"] >= 70
    assert data["confidence"] == "HIGH"
    assert data["attribution"]["actor_identity"] == "NOT ESTABLISHED"
    assert any(s["type"] == "DISPLAY_NAME_DOMAIN_MISMATCH" for s in data["signals"])
    assert any(s["type"] == "REPLY_TO_MISMATCH" for s in data["signals"])

