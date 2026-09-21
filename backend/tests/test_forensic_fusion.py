"""
Tests for ANVESH Phase 9B: Cross-Modal Threat Correlation & Forensic Signal Fusion.

Verifies:
1. Multi-signal high risk case (Content + Identity + Infra + Auth + Intel + Campaign)
2. Compromised mailbox invariant (Auth PASS but Identity deceptive -> CONTRADICTION)
3. Benign internal email (Auth PASS, no threat vectors -> LOW risk)
4. Lookalike + Display Name correlation (Strict Anti-Double-Counting on DOMAIN_IDENTITY)
5. Malicious origin IP + benign content (CONTRADICTION surfaced)
6. Contradiction structure and resolution note enforcement
7. Sparse / missing evidence confidence reduction (LOW confidence)
8. Coordinated campaign correlation points & attribution
9. Compromised mailbox non-attribution invariant (Actor Identity: NOT ESTABLISHED)
10. Empty / minimal inputs robustness (Zero exceptions, score 0, LOW confidence)
"""

import pytest
from app.services.forensic_fusion_service import forensic_fusion_service, CATEGORY_CAPS, INDEPENDENCE_GROUP_CAPS


def test_1_multi_signal_high_risk_synthesis():
    """Test 1: Multi-signal high risk case correctly aggregates across modalities."""
    result = forensic_fusion_service.fuse(
        ml_signal={"ml_score": 25, "ml_factors": ["High credential harvesting intent"]},
        behavior_signal={"behavior_score": 15, "bec_keywords": ["wire transfer"]},
        identity_impersonation={
            "identity_impersonation_score": 85,
            "confidence": "HIGH",
            "observed_identity": "CEO John Doe",
            "observed_sender": "ceo@external-freemail.com",
            "reply_to": "attacker-drop@attacker.net",
            "signals": [
                {"type": "EXECUTIVE_EXTERNAL_DOMAIN", "severity": "HIGH", "points": 35},
                {"type": "REPLY_TO_MISMATCH", "severity": "HIGH", "points": 30}
            ]
        },
        lookalike_evidence={
            "signal": "HIGH",
            "candidate_domain": "paypa1.com",
            "trusted_domain": "paypal.com",
            "deterministic_indicators": ["homoglyph_substitution"]
        },
        auth_context={"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"},
        transport_evidence={"origin_confidence": "HIGH", "relay_count": 8},
        threat_intel={
            "reputation_score": 85,
            "vpn_tor_proxy_indicator": "TOR_EXIT_RELAY",
            "probable_origin_ip": "185.220.101.5"
        },
        campaign={
            "campaign_id": "CMP-2026-ALPHA",
            "confidence": "HIGH",
            "case_count": 4
        }
    )

    assert result["fusion_score"] >= 70
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["fusion_confidence"] == "HIGH"
    assert len(result["primary_signals"]) > 0
    assert len(result["supporting_signals"]) > 0
    assert result["attribution"]["actor_identity"] == "NOT ESTABLISHED"

    # Verify category caps are strictly respected
    breakdown = result["category_breakdown"]
    for cat, cap in CATEGORY_CAPS.items():
        key = cat.lower()
        assert breakdown[key]["score"] <= cap
        assert breakdown[key]["max"] == cap


def test_2_compromised_mailbox_auth_pass_identity_deception():
    """
    Test 2: Compromised mailbox invariant.
    When cryptographic auth PASSES but identity signals are deceptive,
    the contradiction AUTH_PASS_BUT_IDENTITY_SUSPICIOUS must be surfaced.
    """
    result = forensic_fusion_service.fuse(
        ml_signal={"ml_score": 22, "ml_factors": ["Urgent financial requisition"]},
        behavior_signal={"behavior_score": 15, "bec_keywords": ["invoice overdue"]},
        identity_impersonation={
            "identity_impersonation_score": 80,
            "confidence": "HIGH",
            "observed_identity": "Chief Financial Officer",
            "observed_sender": "cfo@legitimate-corporate.com",
            "reply_to": "cfo-external@evil-drop.com",
            "signals": [
                {"type": "REPLY_TO_MISMATCH", "severity": "HIGH", "points": 30}
            ]
        },
        auth_context={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
        threat_intel={"cloud_classification": "MICROSOFT_365_OR_AZURE"}
    )

    # Must detect AUTH_PASS_BUT_IDENTITY_SUSPICIOUS contradiction
    contradiction_types = [c["type"] for c in result["contradictions"]]
    assert "AUTH_PASS_BUT_IDENTITY_SUSPICIOUS" in contradiction_types

    contra = next(c for c in result["contradictions"] if c["type"] == "AUTH_PASS_BUT_IDENTITY_SUSPICIOUS")
    assert "Compromised corporate accounts" in contra["resolution_note"]
    assert "Authentication passed, but identity" in result["forensic_interpretation"]


def test_3_benign_internal_email():
    """Test 3: Benign internal corporate communication yields low risk and zero contradictions."""
    result = forensic_fusion_service.fuse(
        ml_signal={"ml_score": 0, "ml_factors": []},
        behavior_signal={"behavior_score": 0, "bec_keywords": []},
        identity_impersonation={
            "identity_impersonation_score": 0,
            "confidence": "NONE",
            "observed_identity": "HR Team",
            "observed_sender": "hr@company.internal",
            "signals": []
        },
        lookalike_evidence={"signal": "NONE", "candidate_domain": "company.internal"},
        auth_context={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
        transport_evidence={"origin_confidence": "HIGH", "relay_count": 2},
        threat_intel={"reputation_score": 0, "vpn_tor_proxy_indicator": "NONE"}
    )

    assert result["fusion_score"] < 15
    assert result["risk_level"] in ("LOW", "INFORMATIONAL")
    assert len(result["contradictions"]) == 0
    assert result["attribution"]["actor_identity"] == "NOT ESTABLISHED"


def test_4_anti_double_counting_domain_identity():
    """
    Test 4: Strict Anti-Double-Counting.
    Both M3B lookalike and M3A domain mismatch share independence_group 'DOMAIN_IDENTITY'.
    Group points must be capped at 15 points total.
    """
    result = forensic_fusion_service.fuse(
        identity_impersonation={
            "identity_impersonation_score": 75,
            "confidence": "HIGH",
            "observed_identity": "PayPal Security",
            "observed_sender": "security@paypa1.com",
            "signals": [
                {"type": "DISPLAY_NAME_DOMAIN_MISMATCH", "severity": "HIGH", "points": 30},
                {"type": "SUSPICIOUS_SENDER_DOMAIN_RELATION", "severity": "MEDIUM", "points": 15}
            ]
        },
        lookalike_evidence={
            "signal": "HIGH",
            "candidate_domain": "paypa1.com",
            "trusted_domain": "paypal.com",
            "deterministic_indicators": ["homoglyph_substitution"]
        }
    )

    # Find contributions belonging to DOMAIN_IDENTITY
    domain_contribs = [
        c for c in result["contributions"] if c["independence_group"] == "DOMAIN_IDENTITY"
    ]
    total_group_pts = sum(c["contribution"] for c in domain_contribs)

    # Must NOT exceed INDEPENDENCE_GROUP_CAPS["DOMAIN_IDENTITY"]
    max_cap = INDEPENDENCE_GROUP_CAPS["DOMAIN_IDENTITY"]
    assert total_group_pts <= max_cap
    assert result["category_breakdown"]["identity"]["score"] <= CATEGORY_CAPS["IDENTITY"]
    assert result["category_breakdown"]["infrastructure"]["score"] <= CATEGORY_CAPS["INFRASTRUCTURE"]


def test_5_malicious_ip_benign_content_contradiction():
    """
    Test 5: Malicious origin gateway with benign message content
    triggers MALICIOUS_IP_BENIGN_CONTENT contradiction.
    """
    result = forensic_fusion_service.fuse(
        ml_signal={"ml_score": 0, "ml_factors": []},
        behavior_signal={"behavior_score": 0, "bec_keywords": []},
        threat_intel={
            "reputation_score": 85,
            "vpn_tor_proxy_indicator": "TOR_EXIT_RELAY",
            "ip_address": "198.51.100.22"
        }
    )

    contradiction_types = [c["type"] for c in result["contradictions"]]
    assert "MALICIOUS_IP_BENIGN_CONTENT" in contradiction_types
    contra = next(c for c in result["contradictions"] if c["type"] == "MALICIOUS_IP_BENIGN_CONTENT")
    assert "egress proxy" in contra["resolution_note"]


def test_6_contradiction_schema_and_resolution_notes():
    """Test 6: Contradictions conform to required fields and forensic resolution guidance."""
    result = forensic_fusion_service.fuse(
        identity_impersonation={
            "identity_impersonation_score": 70,
            "confidence": "HIGH",
            "signals": [{"type": "REPLY_TO_MISMATCH", "severity": "HIGH", "points": 25}],
            "reply_to": "attacker@evil.com",
            "observed_sender": "ceo@azure-tenant.com"
        },
        auth_context={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
        threat_intel={"cloud_classification": "MICROSOFT_365_OR_AZURE"}
    )

    assert len(result["contradictions"]) >= 1
    for c in result["contradictions"]:
        assert "type" in c
        assert "description" in c
        assert "conflicting_signals" in c
        assert isinstance(c["conflicting_signals"], list)
        assert len(c["conflicting_signals"]) >= 2
        assert "resolution_note" in c
        assert len(c["resolution_note"]) > 10


def test_7_sparse_evidence_reduces_confidence():
    """Test 7: Isolated / sparse evidence results in LOW fusion confidence."""
    result = forensic_fusion_service.fuse(
        ml_signal={"ml_score": 15, "ml_factors": ["Generic urgency"]}
    )

    assert result["fusion_confidence"] == "LOW"
    assert any("Sparse evidence" in r for r in result["confidence_rationale"])


def test_8_coordinated_campaign_correlation():
    """Test 8: Coordinated campaign evidence adds points within CAMPAIGN category cap."""
    result = forensic_fusion_service.fuse(
        campaign={
            "campaign_id": "CMP-FIN-2026",
            "confidence": "HIGH",
            "case_count": 5
        }
    )

    assert result["category_breakdown"]["campaign"]["score"] == 10
    assert result["category_breakdown"]["campaign"]["max"] == 10
    cmp_contribs = [c for c in result["contributions"] if c["category"] == "CAMPAIGN"]
    assert len(cmp_contribs) == 1
    assert "CMP-FIN-2026" in cmp_contribs[0]["description"]


def test_9_compromised_mailbox_non_attribution_invariant():
    """Test 9: Immutable non-attribution boundary invariant enforced unconditionally."""
    result = forensic_fusion_service.fuse(
        identity_impersonation={
            "identity_impersonation_score": 90,
            "confidence": "HIGH",
            "observed_identity": "CEO John",
            "observed_sender": "john@victim-corp.com",
            "signals": [{"type": "REPLY_TO_MISMATCH", "severity": "HIGH", "points": 30}]
        },
        auth_context={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
        threat_intel={"ip_address": "203.0.113.195", "country": "US"}
    )

    attr = result["attribution"]
    assert attr["actor_identity"] == "NOT ESTABLISHED"
    assert "Physical identity of the threat actor is NOT ESTABLISHED" in attr["attribution_boundary"]
    assert "does not establish attacker identity" in result["disclaimer"].lower()


def test_10_empty_minimal_inputs_robustness():
    """Test 10: Service accepts empty or None inputs without raising exceptions."""
    result = forensic_fusion_service.fuse()

    assert result["fusion_score"] == 0
    assert result["risk_level"] in ("LOW", "INFORMATIONAL")
    assert result["fusion_confidence"] == "LOW"
    assert result["attribution"]["actor_identity"] == "NOT ESTABLISHED"
    assert len(result["primary_signals"]) == 0
    assert len(result["contributions"]) == 0
    assert len(result["contradictions"]) == 0
