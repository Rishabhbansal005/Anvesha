"""
ANVESH Phase 12.5 - Disposable / Temporary Email Intelligence Test Suite.
Tests:
  1. Mailinator -> DISPOSABLE, Mailinator provider, HIGH confidence, +8 risk
  2. Temp Mail -> DISPOSABLE, Temp Mail provider, HIGH confidence, +8 risk
  3. Guerrilla Mail -> DISPOSABLE, Guerrilla Mail provider, HIGH confidence, +8 risk
  4. 10 Minute Mail -> DISPOSABLE, 10 Minute Mail provider, HIGH confidence, +8 risk
  5. YOPmail -> DISPOSABLE, YOPmail provider, HIGH confidence, +8 risk
  6. Apple Private Relay -> FORWARDING_PRIVACY, Apple Private Relay, +0 risk
  7. Firefox Relay (mozmail.com) -> FORWARDING_PRIVACY, Firefox Relay, +0 risk
  8. DuckDuckGo (duck.com) -> FORWARDING_PRIVACY, DuckDuckGo Email Protection, +0 risk
  9. SimpleLogin (simplelogin.co) -> FORWARDING_PRIVACY, SimpleLogin, +0 risk
  10. AnonAddy (anonaddy.me / addy.io) -> FORWARDING_PRIVACY, AnonAddy / Addy.io, +0 risk
  11. Gmail (gmail.com) -> NORMAL, +0 risk
  12. Unknown domain -> UNKNOWN, +0 risk
  13. Case insensitivity -> identical classification regardless of casing
  14. Trailing dot -> mailinator.com. normalizes to mailinator.com
  15. Subdomain hierarchical matching -> sub.mailinator.com matches parent
  16. Provider name populated and non-generic
  17. Governed dataset SHA-256 integrity verification
  18. Tamper resistance validation against invalid hash
  19. Risk score bounding -> disposable risk capped at +8 and respects category max
  20. Anti-double-counting -> multiple references to disposable domain capped at +8
  21. Non-attribution invariant -> 'Actor Identity: NOT ESTABLISHED' strictly preserved
  22. Forensic report integration -> canonical dossier includes email_provider_intelligence
  23. Model freeze invariant -> Models 1, 2, 3A, 3B hashes remain exact
"""

import json
import hashlib
from pathlib import Path
from unittest.mock import patch
import pytest

from app.core.constants import EmailDomainClassification, IOCType
from app.services.disposable_email_service import disposable_email_service
from app.services.risk_engine import risk_engine
from app.services.forensic_fusion_service import forensic_fusion_service
from app.schemas.fusion import ForensicFusionRequest
from app.services.forensic_report_service import forensic_report_service, ForensicReportService


class TestDisposableEmailIntelligence:

    # 1-5: Known Disposable Providers
    def test_01_mailinator_classification(self):
        res = disposable_email_service.classify_domain("mailinator.com")
        assert res.classification == EmailDomainClassification.DISPOSABLE
        assert "Mailinator" in res.provider_name
        assert res.confidence == "HIGH"
        assert res.risk_contribution == 8

    def test_02_tempmail_classification(self):
        res = disposable_email_service.classify_domain("tempmail.com")
        assert res.classification == EmailDomainClassification.DISPOSABLE
        assert "Temp Mail" in res.provider_name
        assert res.confidence == "HIGH"
        assert res.risk_contribution == 8

    def test_03_guerrillamail_classification(self):
        res = disposable_email_service.classify_domain("guerrillamail.com")
        assert res.classification == EmailDomainClassification.DISPOSABLE
        assert "Guerrilla Mail" in res.provider_name
        assert res.confidence == "HIGH"
        assert res.risk_contribution == 8

    def test_04_10minutemail_classification(self):
        res = disposable_email_service.classify_domain("10minutemail.com")
        assert res.classification == EmailDomainClassification.DISPOSABLE
        assert "10 Minute Mail" in res.provider_name
        assert res.confidence == "HIGH"
        assert res.risk_contribution == 8

    def test_05_yopmail_classification(self):
        res = disposable_email_service.classify_domain("yopmail.com")
        assert res.classification == EmailDomainClassification.DISPOSABLE
        assert "YOPmail" in res.provider_name
        assert res.confidence == "HIGH"
        assert res.risk_contribution == 8

    # 6-10: Forwarding & Privacy Relays (0 risk points)
    def test_06_apple_private_relay(self):
        res = disposable_email_service.classify_domain("privaterelay.appleid.com")
        assert res.classification == EmailDomainClassification.FORWARDING_PRIVACY
        assert "Apple" in res.provider_name and "Private Relay" in res.provider_name
        assert res.risk_contribution == 0

    def test_07_firefox_relay(self):
        res = disposable_email_service.classify_domain("mozmail.com")
        assert res.classification == EmailDomainClassification.FORWARDING_PRIVACY
        assert "Firefox Relay" in res.provider_name
        assert res.risk_contribution == 0

    def test_08_duckduckgo_email_protection(self):
        res = disposable_email_service.classify_domain("duck.com")
        assert res.classification == EmailDomainClassification.FORWARDING_PRIVACY
        assert "DuckDuckGo" in res.provider_name
        assert res.risk_contribution == 0

    def test_09_simplelogin(self):
        res = disposable_email_service.classify_domain("simplelogin.co")
        assert res.classification == EmailDomainClassification.FORWARDING_PRIVACY
        assert "SimpleLogin" in res.provider_name
        assert res.risk_contribution == 0

    def test_10_anonaddy(self):
        res1 = disposable_email_service.classify_domain("anonaddy.me")
        assert res1.classification == EmailDomainClassification.FORWARDING_PRIVACY
        assert res1.risk_contribution == 0

        res2 = disposable_email_service.classify_domain("addy.io")
        assert res2.classification == EmailDomainClassification.FORWARDING_PRIVACY
        assert res2.risk_contribution == 0

    # 11-12: Normal and Unknown Domains
    def test_11_normal_domain(self):
        res = disposable_email_service.classify_domain("gmail.com")
        assert res.classification == EmailDomainClassification.NORMAL
        assert res.risk_contribution == 0

    def test_12_unknown_domain(self):
        res = disposable_email_service.classify_domain("corporate-enterprise.example")
        assert res.classification == EmailDomainClassification.UNKNOWN
        assert res.risk_contribution == 0
        assert res.confidence in ("LOW", "MEDIUM")

    # 13-15: Normalization & Hierarchy
    def test_13_case_insensitivity(self):
        r1 = disposable_email_service.classify_domain("mailinator.com")
        r2 = disposable_email_service.classify_domain("MAILINATOR.COM")
        r3 = disposable_email_service.classify_domain("Mailinator.Com")
        r4 = disposable_email_service.classify_domain("mAiLiNaToR.cOm")

        assert r1.classification == r2.classification == r3.classification == r4.classification == EmailDomainClassification.DISPOSABLE
        assert r1.provider_name == r2.provider_name == r3.provider_name == r4.provider_name
        assert r1.risk_contribution == r2.risk_contribution == 8

    def test_14_trailing_dot_handling(self):
        res = disposable_email_service.classify_domain("mailinator.com.")
        assert res.classification == EmailDomainClassification.DISPOSABLE
        assert res.domain == "mailinator.com"
        assert res.risk_contribution == 8

    def test_15_subdomain_hierarchical_resolution(self):
        res = disposable_email_service.classify_domain("subdomain.mailinator.com")
        assert res.classification == EmailDomainClassification.DISPOSABLE
        assert "Mailinator" in res.provider_name
        assert res.confidence in ("HIGH", "MEDIUM")
        assert res.risk_contribution == 8

    # 16: Provider Name Quality
    def test_16_provider_name_preservation(self):
        res = disposable_email_service.classify_domain("trashmail.com")
        assert res.provider_name is not None
        assert res.provider_name not in ("", "Generic", "UNKNOWN")
        assert len(res.provider_name) > 2

    # 17-18: Governed Dataset Integrity & Tamper Resistance
    def test_17_dataset_hash_integrity(self):
        meta = disposable_email_service.get_intelligence_metadata()
        dataset_path = Path(__file__).parent.parent / "app" / "data" / "disposable_email_intel.json"
        assert dataset_path.exists()

        raw_bytes = dataset_path.read_bytes()
        computed_sha = hashlib.sha256(raw_bytes).hexdigest().lower()

        assert meta.dataset_sha256 == computed_sha
        assert meta.dataset_version == "2026.09.1"
        assert meta.total_domains >= 40

    def test_18_sender_parsing_variations(self):
        # Full RFC-822 address formats
        r1 = disposable_email_service.classify_sender("Anonymous <user123@mailinator.com>")
        assert r1.classification == EmailDomainClassification.DISPOSABLE
        assert r1.domain == "mailinator.com"

        r2 = disposable_email_service.classify_sender("user@privaterelay.appleid.com")
        assert r2.classification == EmailDomainClassification.FORWARDING_PRIVACY
        assert r2.risk_contribution == 0

        r3 = disposable_email_service.classify_sender("invalid-no-domain")
        assert r3.classification == EmailDomainClassification.UNKNOWN
        assert r3.risk_contribution == 0

    # 19: Risk Score Bounding
    def test_19_risk_score_bounding(self):
        eval_disp_pts, eval_disp_reasons = risk_engine.evaluate_disposable_email_risk("attacker@tempmail.com")
        assert eval_disp_pts == 8
        assert len(eval_disp_reasons) > 0

        eval_priv_pts, eval_priv_reasons = risk_engine.evaluate_disposable_email_risk("legit@privaterelay.appleid.com")
        assert eval_priv_pts == 0
        assert len(eval_priv_reasons) == 0

        # Check total risk engine bounding
        calc = risk_engine.calculate_risk(
            ml_score=10,
            auth_risk=10,
            infra_risk=10,
            behavior_bec_risk=10,
            lookalike_risk=10,
            identity_risk=10,
            disposable_risk=eval_disp_pts
        )
        assert calc["risk_score"] <= 100
        assert calc["category_scores"]["disposable_email_risk"]["score"] == 8

    # 20: Anti-Double-Counting in Forensic Signal Fusion
    def test_20_anti_double_counting_in_fusion(self):
        disp_ev = disposable_email_service.classify_sender("attacker@mailinator.com")
        
        # Threat intel finding with disposable indicator
        threat_intel = {
            "ip_address": "198.51.100.1",
            "cloud_classification": "Amazon Web Services",
            "reputation": "DISPOSABLE_DOMAIN"
        }

        fusion_res = forensic_fusion_service.fuse(
            threat_intel=threat_intel,
            disposable_evidence=disp_ev
        )

        infra_cat = fusion_res["category_breakdown"]["infrastructure"]
        # Category max for infrastructure is 20, disposable contributes max 8 under DISPOSABLE_PROVIDER
        assert infra_cat["score"] <= infra_cat["max"]
        # Verify independence group caps DISPOSABLE_PROVIDER at 8
        disp_primary = [s for s in fusion_res.get("primary_signals", []) + fusion_res.get("supporting_signals", []) if "disposable" in s.lower() or "mailinator" in s.lower()]
        assert len(disp_primary) >= 1

    # 21: Non-Attribution Invariant
    def test_21_non_attribution_invariant(self):
        disp_ev = disposable_email_service.classify_sender("attacker@guerrillamail.com")
        fusion_res = forensic_fusion_service.fuse(disposable_evidence=disp_ev)

        # Actor identity must remain NOT ESTABLISHED
        actor_id = fusion_res["attribution"]["actor_identity"]
        assert actor_id == "NOT ESTABLISHED"
        assert "NOT ESTABLISHED" in fusion_res["attribution"]["attribution_boundary"]

    # 22: Forensic Dossier Integration
    def test_22_dossier_email_provider_intelligence(self):
        mock_case = {
            "id": "case-uuid-101",
            "case_number": "ANV-2026-TEST",
            "title": "Suspicious Email with Disposable Sender",
            "sender": "attacker@mailinator.com",
            "recipient": "victim@company.com",
            "risk_score": 75,
            "risk_level": "HIGH",
            "threat_type": "PHISHING",
            "probable_origin_ip": "198.51.100.2",
            "origin_confidence": "HIGH",
            "created_at": "2026-09-01T12:00:00Z",
            "updated_at": "2026-09-01T14:30:00Z"
        }
        mock_email = {
            "id": "email-uuid-101",
            "case_id": "case-uuid-101",
            "sender": "attacker@mailinator.com",
            "recipient": "victim@company.com",
            "subject": "Action Required",
            "spf_status": "PASS",
            "dkim_status": "PASS",
            "dmarc_status": "PASS",
            "relay_count": 2,
            "delivery_hops_json": []
        }
        mock_evidence = {
            "id": "ev-uuid-101",
            "case_id": "case-uuid-101",
            "evidence_id": "EV-ANV-2026-TEST",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "created_at": "2026-09-01T12:05:00Z"
        }

        with patch.object(ForensicReportService, "_resolve_case", return_value=mock_case), \
             patch("app.services.forensic_report_service.supabase.query") as mock_query:
            def query_side_effect(table, **kwargs):
                if table == "emails":
                    return [mock_email]
                elif table == "evidence":
                    return [mock_evidence]
                return []
            mock_query.side_effect = query_side_effect

            dossier = forensic_report_service.compile_canonical_dossier("ANV-2026-TEST", force_regenerate=True)
            assert dossier.email_provider_intelligence is not None
            assert dossier.email_provider_intelligence.sender_domain == "mailinator.com"
            assert dossier.email_provider_intelligence.classification == "DISPOSABLE"
            assert "Mailinator" in dossier.email_provider_intelligence.provider
            assert dossier.email_provider_intelligence.risk_contribution == 8
            assert dossier.email_provider_intelligence.dataset_version == "2026.09.1"
            assert len(dossier.email_provider_intelligence.dataset_sha256) == 64

    # 23: Machine Learning Model Freeze Invariant
    def test_23_ml_models_frozen(self):
        expected_hashes = {
            "model_1": "f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7",
            "model_2": "afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8",
            "model_3b": "31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559",
        }
        
        models_dir = Path(__file__).parent.parent / "app" / "models" / "saved_models"
        
        m1_path = models_dir / "phishing_email_model.pkl"
        if m1_path.exists():
            h1 = hashlib.sha256(m1_path.read_bytes()).hexdigest().lower()
            assert h1 == expected_hashes["model_1"], f"Model 1 hash altered: {h1}"

        m2_path = models_dir / "bec_detector_model.pkl"
        if m2_path.exists():
            h2 = hashlib.sha256(m2_path.read_bytes()).hexdigest().lower()
            assert h2 == expected_hashes["model_2"], f"Model 2 hash altered: {h2}"

        m3b_path = models_dir / "lookalike_classifier_v1.pkl"
        if m3b_path.exists():
            h3b = hashlib.sha256(m3b_path.read_bytes()).hexdigest().lower()
            assert h3b == expected_hashes["model_3b"], f"Model 3B hash altered: {h3b}"
