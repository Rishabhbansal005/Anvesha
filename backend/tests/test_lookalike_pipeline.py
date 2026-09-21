"""
ANVESH Phase 7F - Model 3B Lookalike Detection Pipeline Tests.

Tests:
1. Exact legitimate domain (AUTHENTIC_DOMAIN)
2. Normal typosquatting detection
3. Digit substitution detection
4. Hyphen manipulation detection
5. Homoglyph Unicode attack (Tier 1 deterministic override)
6. Punycode RFC-3492 attack (Tier 1 deterministic override)
7. Subdomain lure deception (Tier 1 deterministic override)
8. Model hash mismatch / integrity failure (Fails Closed)
9. Raw score labeling and uncalibrated probability compliance
10. Model unavailable failure path handling
"""

import sys
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from ml.inference.lookalike_predictor import (
    LookalikePredictor,
    ModelIntegrityError,
    EXPECTED_MODEL_SHA256,
    DEFAULT_MODEL_PATH
)
from backend.app.services.lookalike_service import LookalikeService, lookalike_service


@pytest.fixture
def predictor():
    return LookalikePredictor()


def test_1_exact_legitimate_domain(predictor):
    """Test 1: Exact matching candidate and trusted domain produces AUTHENTIC_DOMAIN and NONE signal."""
    res = predictor.predict(trusted_domain="apple.com", candidate_domain="apple.com")
    assert res["signal"] == "NONE"
    assert res["raw_model_score"] == 0.0
    assert "AUTHENTIC_DOMAIN" in res["deterministic_indicators"]
    assert res["features"]["normalized_edit_distance"] == 0.0
    assert res["features"]["jaro_winkler"] == 1.0


def test_2_normal_typosquat(predictor):
    """Test 2: Standard typosquat (e.g. micros0ft.com) produces HIGH lookalike signal."""
    res = predictor.predict(trusted_domain="microsoft.com", candidate_domain="micros0ft.com")
    assert res["signal"] == "HIGH"
    assert res["raw_model_score"] > 0.50
    assert res["features"]["levenshtein_distance"] >= 1


def test_3_digit_substitution(predictor):
    """Test 3: Leet-speak digit substitution (paypa1.com for paypal.com) detected."""
    res = predictor.predict(trusted_domain="paypal.com", candidate_domain="paypa1.com")
    assert res["signal"] == "HIGH"
    assert res["features"]["digit_substitution_count"] == 1.0


def test_4_hyphen_manipulation(predictor):
    """Test 4: Hyphen keyword manipulation detected."""
    res = predictor.predict(trusted_domain="paypal.com", candidate_domain="paypal-security.com")
    assert res["signal"] == "HIGH"
    assert res["features"]["hyphen_count_diff"] >= 1.0


def test_5_homoglyph_attack(predictor):
    """Test 5: Critical test - Cyrillic homoglyph (рayрal.com) triggers HOMOGLYPH_DECEPTION and remains HIGH."""
    res = predictor.predict(trusted_domain="paypal.com", candidate_domain="рayрal.com")
    assert "HOMOGLYPH_DECEPTION" in res["deterministic_indicators"]
    assert res["signal"] == "HIGH"
    assert res["features"]["has_homoglyph"] == 1.0


def test_6_punycode_attack(predictor):
    """Test 6: Critical test - Punycode (xn--pple-43d.com) triggers PUNYCODE_IDN_SPOOF and remains HIGH."""
    res = predictor.predict(trusted_domain="apple.com", candidate_domain="xn--pple-43d.com")
    assert "PUNYCODE_IDN_SPOOF" in res["deterministic_indicators"]
    assert res["signal"] == "HIGH"
    assert res["features"]["is_punycode"] == 1.0


def test_7_subdomain_lure(predictor):
    """Test 7: Subdomain lure (paypal.com.account-verify.xyz) triggers SUBDOMAIN_LURE and remains HIGH."""
    res = predictor.predict(trusted_domain="paypal.com", candidate_domain="paypal.com.account-verify.xyz")
    assert "SUBDOMAIN_LURE" in res["deterministic_indicators"]
    assert res["signal"] == "HIGH"
    assert res["features"]["brand_in_subdomain"] == 1.0


def test_8_model_hash_mismatch_fails_closed(tmp_path):
    """Test 8: If model artifact hash does not match EXPECTED_MODEL_SHA256, fail closed with ModelIntegrityError."""
    corrupted_model_file = tmp_path / "model.joblib"
    corrupted_model_file.write_bytes(b"corrupted or tampered weights")

    with pytest.raises(ModelIntegrityError):
        LookalikePredictor(model_path=corrupted_model_file)


def test_9_raw_score_labeling_compliance(predictor):
    """Test 9: Output schema labels score as raw_model_score, never calibrated probability."""
    res = predictor.predict(trusted_domain="google.com", candidate_domain="g00gle.com")
    assert "raw_model_score" in res
    assert "probability" not in res
    assert "calibrated_probability" not in res
    assert isinstance(res["raw_model_score"], float)
    assert 0.0 <= res["raw_model_score"] <= 1.0


def test_10_model_unavailable_fallback():
    """Test 10: Service fallback gracefully returns UNKNOWN status when model is unavailable."""
    service = LookalikeService()
    # Simulate unavailable predictor
    service.available = False
    service.predictor = None

    fallback_res = service.detect_lookalike("candidate.com", "trusted.com")
    assert fallback_res["signal"] == "UNKNOWN"
    assert fallback_res["model_status"] == "UNAVAILABLE"
    assert "SERVICE_UNAVAILABLE" in fallback_res["deterministic_indicators"]


def test_11_fastapi_lookalike_endpoint():
    """Test 11: FastAPI endpoint POST /api/v1/emails/lookalike-detect returns expected Model 3B schema."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    response = client.post(
        "/api/v1/emails/lookalike-detect",
        json={"candidate_domain": "xn--pple-43d.com", "trusted_domain": "apple.com"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["model"] == "lookalike_domain_v1"
    assert data["signal"] == "HIGH"
    assert "PUNYCODE_IDN_SPOOF" in data["deterministic_indicators"]
    assert "raw_model_score" in data
    assert "features" in data
