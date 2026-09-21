"""
Unit tests for ANVESH Real RFC-822 Email Ingestion Pipeline.
Uses isolated test fixtures under backend/tests/fixtures/.
"""
import os
import pytest
from app.services.risk_engine import risk_engine


def test_fixture_parsing():
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "test_bec_email.eml")
    assert os.path.exists(fixture_path), "Test fixture must exist"
    
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert "185.220.101.42" in content
    assert "spf=fail" in content
    assert "dkim=fail" in content
    assert "wire transfer" in content.lower()


def test_deterministic_risk_scoring():
    res = risk_engine.calculate_risk(
        ml_score=20,
        auth_risk=25,
        infra_risk=15,
        behavior_bec_risk=20,
        reasons=["SPF failed", "DKIM failed", "BEC keywords"]
    )
    assert 0 <= res["risk_score"] <= 100
    assert res["risk_level"] in ("CRITICAL", "HIGH")
    assert len(res["reasons"]) == 3


def test_ml_classifier_scoring():
    from app.services.risk_engine import ml_classifier
    res = ml_classifier.classify(
        text="Please execute confidential wire transfer for pending acquisition immediately before market close.",
        sender='"Dr. Rajesh Sharma" <rajesh@protonmail.com>',
        subject="URGENT: Escrow Wire Instructions"
    )
    assert res["ml_score"] > 0
    assert res["ml_probability"] > 0.0
    assert len(res["ml_factors"]) >= 2
    assert "wire transfer" in str(res["ml_factors"]).lower()
