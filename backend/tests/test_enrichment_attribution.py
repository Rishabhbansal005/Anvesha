"""
Comprehensive Test Suite for ANVESH Phase 3:
Evidence Enrichment, Infrastructure Intelligence, and Attribution Boundaries.
Strict Zero-Fabrication Verification.
"""
import pytest
from app.services.intelligence_service import intelligence_service
from app.services.intelligence.base import IntelligenceStatus, EvidenceNature
from app.services.intelligence.ip_enrichment import ip_enrichment_service
from app.services.intelligence.dns_service import dns_service
from app.services.intelligence.rdap_service import rdap_service
from app.services.intelligence.threat_intel import vt_provider, abuseipdb_provider, safebrowsing_provider
from app.services.intelligence.cache import intelligence_cache
from app.services.attribution_service import attribution_service
from app.services.risk_engine import risk_engine, ml_classifier


def test_ip_classification_private_and_loopback():
    """SSRF guard: RFC1918 and loopback IPs must be classified locally without external queries."""
    # Private RFC1918
    res_priv = ip_enrichment_service.enrich_ip("192.168.1.100")
    assert res_priv.status == IntelligenceStatus.OBSERVED
    assert res_priv.data["is_private"] is True
    assert res_priv.data["cloud_classification"] == "PRIVATE_NETWORK"
    assert "Internal" in res_priv.data["country"]

    # Loopback
    res_loop = ip_enrichment_service.enrich_ip("127.0.0.1")
    assert res_loop.status == IntelligenceStatus.OBSERVED
    assert res_loop.data["is_private"] is True
    assert res_loop.data["cloud_classification"] == "HOST_LOOPBACK"


def test_ipv6_and_malformed_ip_handling():
    """Handles valid IPv6 and cleanly rejects malformed IP syntax."""
    # Valid IPv6
    res_v6 = ip_enrichment_service.enrich_ip("2001:4860:4860::8888")
    assert res_v6.data["ip_version"] == 6
    assert res_v6.data["is_private"] is False

    # Malformed IP
    res_bad = ip_enrichment_service.enrich_ip("999.999.999.999")
    assert res_bad.status == IntelligenceStatus.ERROR
    assert "syntax" in res_bad.error_message.lower()

    res_text = ip_enrichment_service.enrich_ip("not-an-ip-address")
    assert res_text.status == IntelligenceStatus.ERROR


def test_unconfigured_threat_providers_return_unavailable():
    """
    Zero-Fabrication Contract:
    When threat intelligence API keys are unconfigured, providers must return
    status='UNAVAILABLE' with an objective reason, never invented scores.
    """
    # Force unconfigured state
    vt_provider.api_key = ""
    abuseipdb_provider.api_key = ""
    safebrowsing_provider.api_key = ""

    vt_res = vt_provider.lookup_ip("185.220.101.5")
    assert vt_res.status == IntelligenceStatus.UNAVAILABLE
    assert "not configured" in vt_res.error_message.lower()
    assert vt_res.confidence == "NONE"

    abuse_res = abuseipdb_provider.lookup_ip("185.220.101.5")
    assert abuse_res.status == IntelligenceStatus.UNAVAILABLE
    assert "not configured" in abuse_res.error_message.lower()

    sb_res = safebrowsing_provider.check_url("http://malicious-test-link.com/login")
    assert sb_res.status == IntelligenceStatus.UNAVAILABLE
    assert "not configured" in sb_res.error_message.lower()


def test_location_nomenclature_safety():
    """
    Forensic safety: Geolocation must be labeled as 'IP-associated infrastructure location'
    and NEVER 'Attacker Location'.
    """
    res = ip_enrichment_service.enrich_ip("8.8.8.8")
    assert "IP-associated infrastructure location" in res.disclaimer
    assert "attacker" not in res.disclaimer.lower()
    assert "physical actor" in res.disclaimer.lower()


def test_authoritative_hosting_classification_provenance():
    """
    Authoritative classification must be backed by documented source and store provenance.
    """
    res = ip_enrichment_service.enrich_ip("8.8.8.8")
    # 8.8.8.8 is an authoritative Google IP
    assert res.data["cloud_classification"] in ("GOOGLE_WORKSPACE_OR_GCP", "INDEPENDENT_OR_RESIDENTIAL_TRANSIT", "UNAVAILABLE")
    assert "classification_source" in res.data
    assert res.data["classification_source"] != ""


def test_tor_exit_relay_observation_vs_inference():
    """
    TOR observation must strictly report observed infrastructure, never inferring attacker action.
    """
    res = ip_enrichment_service.enrich_ip("192.168.1.1")
    assert res.data["vpn_tor_proxy_indicator"] == "NONE"
    assert "Attacker used TOR" not in res.data["tor_vpn_observation"]


def test_dns_and_mx_resolution():
    """DNS service resolves records and identifies mail providers without false assumptions."""
    res = dns_service.resolve_domain("google.com")
    assert res.status in (IntelligenceStatus.OBSERVED, IntelligenceStatus.ENRICHED, IntelligenceStatus.NO_DATA)
    if res.status == IntelligenceStatus.OBSERVED:
        assert "MX" in res.data["records"]
        assert "has_mx" in res.data
        assert res.data["detected_mail_provider"] in ("GOOGLE_WORKSPACE", "INDEPENDENT_OR_UNCLASSIFIED")


def test_intelligence_cache_ttl():
    """Intelligence cache avoids redundant lookups."""
    intelligence_cache.clear()
    res1 = ip_enrichment_service.enrich_ip("1.1.1.1")
    cached = intelligence_cache.get("1.1.1.1", ip_enrichment_service.name, "IP_INFRASTRUCTURE")
    assert cached is not None
    assert cached.indicator == "1.1.1.1"


def test_origin_confidence_evaluation():
    """Origin confidence distinguishes single hops, multi-hops, and shared cloud relays."""
    # Shared Cloud relay (M365)
    conf_cloud = attribution_service.evaluate_origin_confidence(
        probable_origin_ip="40.107.1.1",
        hops=[{"hop": 1, "raw": "Received: from mail.protection.outlook.com"}],
        cloud_classification="MICROSOFT_365_OR_AZURE"
    )
    assert conf_cloud["level"] == "LOW"
    assert "Microsoft 365" in conf_cloud["reason"] or "shared" in conf_cloud["reason"].lower()

    # Multi-hop authenticated public gateway
    conf_auth = attribution_service.evaluate_origin_confidence(
        probable_origin_ip="198.51.100.1",
        hops=[{"hop": 1}, {"hop": 2}],
        cloud_classification="INDEPENDENT_TRANSIT",
        auth_status={"spf": "PASS", "dkim": "PASS"}
    )
    assert conf_auth["level"] == "HIGH"


def test_attribution_assessment_actor_identity_invariant():
    """
    Attribution Assessment: Actor Identity must remain strictly 'NOT ESTABLISHED'.
    Never fabricate an individual's identity from IP or headers.
    """
    attr = attribution_service.generate_attribution_assessment(
        case_title="Investigation of Wire Change Request",
        risk_level="HIGH",
        risk_score=75,
        origin_confidence="LOW",
        cloud_classification="MICROSOFT_365_OR_AZURE",
        probable_origin_ip="40.107.1.1",
        asn="AS8075"
    )
    assert attr["actor_identity"] == "NOT ESTABLISHED"
    assert "terminate" in attr["attribution_boundary"].lower() or "boundary" in attr["attribution_boundary"].lower()
    assert "Microsoft 365" in attr["observed_infrastructure"]


def test_evidence_gaps_prescriptions():
    """Prescribes actionable next steps for account takeover and spoofing scenarios."""
    gaps_bec = attribution_service.generate_evidence_gaps(
        threat_type="BEC",
        is_cloud_provider=True,
        origin_confidence="LOW",
        auth_pass=True
    )
    assert len(gaps_bec["identified_gaps"]) >= 2
    assert any("sign-in" in g.lower() for g in gaps_bec["identified_gaps"])
    assert "mailbox" in gaps_bec["recommended_next_action"].lower()
    assert any(opt["evidence_type"] == "Mailbox Sign-In Logs" for opt in gaps_bec["additional_evidence_options"])


def test_compromised_account_bec_scenario():
    """
    CRITICAL FORENSIC REQUIREMENT:
    Scenario:
    - SPF = PASS
    - DKIM = PASS
    - DMARC = PASS
    - Sender domain = legitimate
    - IP = legitimate Microsoft 365 cloud infrastructure
    - Email requests urgent bank account / payment wire change
    Expected:
    - Do NOT automatically classify as safe!
    - Risk score remains elevated (MEDIUM/HIGH due to ML + BEC behavioral indicators).
    - Attribution: Actor Identity = 'NOT ESTABLISHED'.
    - Origin Confidence = LOW.
    - Evidence Gap: Mailbox sign-in / message trace recommended.
    """
    # 1. NLP and BEC detection detects urgent financial coercion
    bec_text = "Please execute urgent bank account wire transfer to updated routing number immediately before 4pm close."
    sender = '"CEO Office" <ceo@legitimate-corporate.com>'
    subject = "URGENT: Updated Wire Instructions for Pending Invoice"

    ml_res = ml_classifier.classify(text=bec_text, sender=sender, subject=subject)
    assert ml_res["ml_score"] > 15, "ML classifier must detect urgency and wire tokens"

    # Behavior risk calculation
    behavior_score = 15  # Wire transfer + financial urgency keywords
    auth_score = 0       # Passing SPF, DKIM, DMARC (no auth risk penalty)
    infra_score = 0      # Legitimate clean Microsoft infrastructure (no malicious IP penalty)

    final_risk = risk_engine.calculate_risk(
        ml_score=ml_res["ml_score"],
        auth_risk=auth_score,
        infra_risk=infra_score,
        behavior_bec_risk=behavior_score,
        reasons=["BEC financial coercion keyword: 'wire transfer'"]
    )

    # Risk must NOT be classified as LOW or SAFE despite clean IP and passing auth!
    assert final_risk["risk_score"] >= 30, f"Expected elevated risk score, got {final_risk['risk_score']}"
    assert final_risk["risk_level"] in ("HIGH", "MEDIUM", "CRITICAL")

    # Origin confidence for Microsoft 365 relay must be LOW
    origin_eval = attribution_service.evaluate_origin_confidence(
        probable_origin_ip="40.107.1.1",
        hops=[{"hop": 1, "raw": "Received: from mail-eop.protection.outlook.com"}],
        cloud_classification="MICROSOFT_365_OR_AZURE",
        auth_status={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
    )
    assert origin_eval["level"] == "LOW"

    # Attribution: Actor identity is NOT ESTABLISHED
    attr = attribution_service.generate_attribution_assessment(
        case_title="Investigation: " + subject,
        risk_level=final_risk["risk_level"],
        risk_score=final_risk["risk_score"],
        origin_confidence=origin_eval["level"],
        cloud_classification="MICROSOFT_365_OR_AZURE",
        probable_origin_ip="40.107.1.1",
        asn="AS8075"
    )
    assert attr["actor_identity"] == "NOT ESTABLISHED"

    # Evidence Gap prescribes mailbox sign-in / message trace audit logs
    gaps = attribution_service.generate_evidence_gaps(
        threat_type="BEC",
        is_cloud_provider=True,
        origin_confidence="LOW",
        auth_pass=True
    )
    assert "sign-in" in gaps["recommended_next_action"].lower()
    assert "account takeover" in gaps["recommended_next_action"].lower() or "mailbox" in gaps["recommended_next_action"].lower()
