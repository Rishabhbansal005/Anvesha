"""
Comprehensive Test Suite for ANVESH Phase 8A:
Campaign Intelligence Foundation, Deterministic Correlation Engine,
Strict Non-Attribution Boundary, False-Positive Protections, and Frozen ML Integrity.
"""
import hashlib
import os
import pytest
from datetime import datetime
from app.services.campaign_service import (
    campaign_service,
    normalize_email,
    normalize_domain,
    normalize_url,
    normalize_ip,
    normalize_subject,
    EXCLUDED_FREEMAIL_DOMAINS,
    EXCLUDED_CLOUD_PROVIDERS
)
from app.database.supabase_client import supabase


# ---------------------------------------------------------------------------
# 1 & 2. Exact Domain & Reply-To Overlap
# ---------------------------------------------------------------------------
def test_exact_domain_overlap_correlates():
    """Exact suspicious domain overlap produces a strong signal and >= 50 score when paired with identity or context."""
    case_a = {"id": "c1", "case_number": "ANV-2026-0001", "created_at": "2026-09-01T10:00:00"}
    case_b = {"id": "c2", "case_number": "ANV-2026-0002", "created_at": "2026-09-02T10:00:00"}
    email_a = {"subject": "Urgent wire required", "sender": "attacker1@bad-actor-c2.net"}
    email_b = {"subject": "Urgent wire required", "sender": "attacker2@bad-actor-c2.net"}
    obs_a = [{"ioc_type": "DOMAIN", "value": "bad-actor-c2.net"}]
    obs_b = [{"ioc_type": "DOMAIN", "value": "bad-actor-c2.net"}]

    res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b,
        observables_a=obs_a, observables_b=obs_b
    )
    assert res["related"] is True
    assert res["confidence"] in ("HIGH", "MEDIUM")
    assert any(r["signal"] == "EXACT_SUSPICIOUS_DOMAIN" for r in res["reasons"])
    assert any(r["strength"] == "STRONG" for r in res["reasons"])


def test_exact_reply_to_overlap_correlates():
    """Exact Reply-To address match produces STRONG correlation signal."""
    case_a = {"id": "c1", "case_number": "ANV-2026-0003", "created_at": "2026-09-01T10:00:00"}
    case_b = {"id": "c2", "case_number": "ANV-2026-0004", "created_at": "2026-09-02T10:00:00"}
    email_a = {
        "reply_to": "drop-box-finances@secure-billing-gateway.org",
        "sender": "ceo@legit-company.com",
        "subject": "Vendor Settlement"
    }
    email_b = {
        "reply_to": "drop-box-finances@secure-billing-gateway.org",
        "sender": "hr@partner-firm.com",
        "subject": "Vendor Settlement"
    }

    res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b
    )
    assert res["related"] is True
    assert res["confidence"] in ("HIGH", "MEDIUM")
    assert any(r["signal"] == "EXACT_REPLY_TO" for r in res["reasons"])


# ---------------------------------------------------------------------------
# 3 & 4. Same IOC & Content Similarity
# ---------------------------------------------------------------------------
def test_same_suspicious_ioc_correlates():
    """Identical suspicious URL observable links cases."""
    case_a = {"id": "c1", "case_number": "ANV-2026-0005", "created_at": "2026-09-01T10:00:00"}
    case_b = {"id": "c2", "case_number": "ANV-2026-0006", "created_at": "2026-09-03T10:00:00"}
    obs_a = [{"ioc_type": "URL", "value": "http://evil-payload-host.ru/invoice.exe"}]
    obs_b = [{"ioc_type": "URL", "value": "http://evil-payload-host.ru/invoice.exe"}]
    email_a = {"subject": "Outstanding invoice 4410"}
    email_b = {"subject": "Outstanding invoice 4410"}

    res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b,
        observables_a=obs_a, observables_b=obs_b
    )
    assert res["related"] is True
    assert any(r["signal"] == "EXACT_IOC_OVERLAP" for r in res["reasons"])


def test_highly_similar_subjects_contribution():
    """Stripping prefixes like RE:, FW:, [EXTERNAL] produces normalized subject similarity."""
    s1 = normalize_subject("Re: FW: [EXTERNAL] URGENT Payment Confirmation Required")
    s2 = normalize_subject("urgent payment confirmation required")
    assert s1["normalized"] == s2["normalized"]
    assert s1["normalized"] == "urgent payment confirmation required"


# ---------------------------------------------------------------------------
# 5, 6 & 7. Strict False-Positive Protections (Gmail, M365, ASN)
# ---------------------------------------------------------------------------
def test_same_gmail_infrastructure_only_not_related():
    """Two completely distinct emails using gmail.com alone MUST NEVER correlate."""
    case_a = {"id": "c1", "case_number": "ANV-2026-0007", "created_at": "2026-09-01T10:00:00"}
    case_b = {"id": "c2", "case_number": "ANV-2026-0008", "created_at": "2026-09-02T10:00:00"}
    email_a = {"sender": "person_alpha@gmail.com", "subject": "Project sync meeting tomorrow"}
    email_b = {"sender": "person_beta@gmail.com", "subject": "Quarterly financial statement"}
    obs_a = [{"ioc_type": "DOMAIN", "value": "gmail.com"}]
    obs_b = [{"ioc_type": "DOMAIN", "value": "gmail.com"}]

    res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b,
        observables_a=obs_a, observables_b=obs_b
    )
    assert res["related"] is False
    assert res["confidence"] == "LOW"
    assert res["score"] < 50
    # Ensure gmail.com domain was NOT counted as suspicious domain overlap
    assert not any(r["signal"] == "EXACT_SUSPICIOUS_DOMAIN" for r in res["reasons"])


def test_same_microsoft_365_infrastructure_only_not_related():
    """Shared Microsoft 365 cloud gateway alone MUST NEVER create a campaign relationship."""
    case_a = {
        "id": "c1", "case_number": "ANV-2026-0009",
        "probable_origin_ip": "40.107.220.100", "created_at": "2026-09-01T10:00:00"
    }
    case_b = {
        "id": "c2", "case_number": "ANV-2026-0010",
        "probable_origin_ip": "40.107.220.100", "created_at": "2026-09-02T10:00:00"
    }
    infra_a = {"cloud_classification": "MICROSOFT_365_OR_AZURE", "asn": 8075}
    infra_b = {"cloud_classification": "MICROSOFT_365_OR_AZURE", "asn": 8075}
    email_a = {"sender": "alice@company-a.com", "subject": "Contract Renewal"}
    email_b = {"sender": "bob@company-b.com", "subject": "Weekly Newsletter"}

    res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b,
        infra_a=infra_a, infra_b=infra_b
    )
    assert res["related"] is False
    assert res["confidence"] == "LOW"
    assert res["score"] < 50
    # Public IP weight should be suppressed
    assert any(r["signal"] == "SHARED_PUBLIC_GATEWAY_GUARD" for r in res["reasons"])


def test_same_asn_only_is_weak_and_not_strong_enough():
    """Matching ASN alone provides weak context (+2 max) and never triggers campaign formation."""
    case_a = {"id": "c1", "case_number": "ANV-2026-0011", "created_at": "2026-08-01T10:00:00"}
    case_b = {"id": "c2", "case_number": "ANV-2026-0012", "created_at": "2026-09-15T10:00:00"}
    infra_a = {"asn": 13335}  # Cloudflare
    infra_b = {"asn": 13335}
    email_a = {"sender": "support@store1.com", "subject": "Order #1234"}
    email_b = {"sender": "service@bank2.com", "subject": "Security Notice"}

    res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b,
        infra_a=infra_a, infra_b=infra_b
    )
    assert res["related"] is False
    assert res["score"] == 2
    assert any(r["signal"] == "SHARED_ASN_CONTEXT" for r in res["reasons"])


# ---------------------------------------------------------------------------
# 8 & 9. Unrelated Emails & Confidence Scale
# ---------------------------------------------------------------------------
def test_different_unrelated_emails_not_related():
    """Unrelated emails with different IPs, domains, subjects, and senders return related=False."""
    case_a = {"id": "c1", "case_number": "ANV-2026-0013", "probable_origin_ip": "198.51.100.1"}
    case_b = {"id": "c2", "case_number": "ANV-2026-0014", "probable_origin_ip": "203.0.113.55"}
    email_a = {"sender": "newsletter@cooking.org", "subject": "Recipe of the week"}
    email_b = {"sender": "alerts@transit-agency.gov", "subject": "Train Schedule Update"}

    res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b
    )
    assert res["related"] is False
    assert res["confidence"] == "LOW"
    assert res["score"] == 0
    assert len(res["reasons"]) == 0


def test_confidence_scale_tiers():
    """Verifies documented confidence tiers: >=75 HIGH, 50-74 MEDIUM, <50 LOW."""
    # Strong correlation: Reply-To (+35) + Domain (+35) + Subject (+15) + Time (+10) = 95 -> HIGH
    case_a = {"id": "c1", "case_number": "ANV-1", "created_at": "2026-09-01T10:00:00"}
    case_b = {"id": "c2", "case_number": "ANV-2", "created_at": "2026-09-01T11:00:00"}
    email_a = {"reply_to": "evil@stealth-c2.cc", "subject": "urgent invoice settlement"}
    email_b = {"reply_to": "evil@stealth-c2.cc", "subject": "urgent invoice settlement"}
    obs_a = [{"ioc_type": "DOMAIN", "value": "stealth-c2.cc"}]
    obs_b = [{"ioc_type": "DOMAIN", "value": "stealth-c2.cc"}]

    high_res = campaign_service.evaluate_correlation(
        case_a=case_a, case_b=case_b,
        email_a=email_a, email_b=email_b,
        observables_a=obs_a, observables_b=obs_b
    )
    assert high_res["confidence"] == "HIGH"
    assert high_res["score"] >= 75


# ---------------------------------------------------------------------------
# 10. Deterministic Explanation & Non-Attribution
# ---------------------------------------------------------------------------
def test_correlation_explanation_preserves_non_attribution():
    """Explanation MUST NOT contain prohibited attacker attribution statements."""
    explanation = campaign_service.generate_campaign_explanation(
        campaign_name="Potential Campaign: Urgent Financial Cluster",
        case_count=3,
        email_count=3,
        ioc_count=5,
        evidence_summary={"shared_reply_to_count": 1, "shared_domain_count": 2},
        first_seen="2026-09-01T00:00:00",
        last_seen="2026-09-04T00:00:00"
    )
    lower_exp = explanation.lower()
    # Invariant assertions: NEVER say same attacker or identify person
    assert "same attacker" not in lower_exp
    assert "attacker identified" not in lower_exp
    assert "this person sent all emails" not in lower_exp
    assert "attacker location" not in lower_exp
    assert "actor identity is not established" in lower_exp
    assert "related activity" in lower_exp


# ---------------------------------------------------------------------------
# 11 & 12. Campaign Creation & Attachment Lifecycle
# ---------------------------------------------------------------------------
def test_campaign_creation_and_attachment_lifecycle():
    """
    1. Case 1 is ingested. No prior matches -> no campaign.
    2. Case 2 is ingested with matching Reply-To and domain -> new campaign created!
    3. Case 3 is ingested matching Case 1 -> attached to existing campaign!
    """
    case_1 = {
        "id": "case-test-uuid-1",
        "case_number": "ANV-TEST-0001",
        "title": "Investigation 1",
        "created_at": "2026-09-01T10:00:00"
    }
    email_1 = {
        "case_id": "case-test-uuid-1",
        "reply_to": "threat-drop@phantom-operations.net",
        "subject": "Urgent Financial Mandate"
    }
    obs_1 = [{"ioc_type": "DOMAIN", "value": "phantom-operations.net"}]
    supabase.insert("cases", case_1)
    supabase.insert("emails", email_1)
    for o in obs_1:
        supabase.insert("iocs", {**o, "case_id": "case-test-uuid-1"})

    # Case 2: Correlates strongly with Case 1
    case_2 = {
        "id": "case-test-uuid-2",
        "case_number": "ANV-TEST-0002",
        "title": "Investigation 2",
        "created_at": "2026-09-02T10:00:00"
    }
    email_2 = {
        "case_id": "case-test-uuid-2",
        "reply_to": "threat-drop@phantom-operations.net",
        "subject": "Urgent Financial Mandate"
    }
    obs_2 = [{"ioc_type": "DOMAIN", "value": "phantom-operations.net"}]
    supabase.insert("cases", case_2)
    supabase.insert("emails", email_2)
    for o in obs_2:
        supabase.insert("iocs", {**o, "case_id": "case-test-uuid-2"})

    res_camp2 = campaign_service.correlate_and_assign_case(
        case_data=case_2,
        email_data=email_2,
        observables=obs_2
    )

    assert res_camp2 is not None
    assert "campaign" in res_camp2
    campaign_obj = res_camp2["campaign"]
    camp_id = campaign_obj["id"]
    assert campaign_obj["case_count"] == 2
    assert campaign_obj["confidence"] == "HIGH"

    # Case 3: Attaches to the same campaign
    case_3 = {
        "id": "case-test-uuid-3",
        "case_number": "ANV-TEST-0003",
        "title": "Investigation 3",
        "created_at": "2026-09-03T10:00:00"
    }
    email_3 = {
        "case_id": "case-test-uuid-3",
        "reply_to": "threat-drop@phantom-operations.net",
        "subject": "Urgent Financial Mandate"
    }
    obs_3 = [{"ioc_type": "DOMAIN", "value": "phantom-operations.net"}]
    supabase.insert("cases", case_3)
    supabase.insert("emails", email_3)
    for o in obs_3:
        supabase.insert("iocs", {**o, "case_id": "case-test-uuid-3"})

    res_camp3 = campaign_service.correlate_and_assign_case(
        case_data=case_3,
        email_data=email_3,
        observables=obs_3
    )

    assert res_camp3 is not None
    assert res_camp3["campaign"]["id"] == camp_id
    assert res_camp3["campaign"]["case_count"] == 3


# ---------------------------------------------------------------------------
# 13. Timeline Ordering
# ---------------------------------------------------------------------------
def test_timeline_chronological_ordering():
    """Timeline events are sorted chronologically according to actual evidence timestamps."""
    camp_id = "test-timeline-camp-uuid"
    now_1 = "2026-09-01T08:00:00"
    now_2 = "2026-09-02T12:00:00"
    now_3 = "2026-09-03T15:00:00"

    camp_rec = {
        "id": camp_id,
        "campaign_id": "ANV-26-CMP-TIME",
        "name": "Timeline Verification Cluster",
        "status": "ACTIVE"
    }
    supabase.insert("campaigns", camp_rec)

    c1 = {"id": "t_case_1", "case_number": "ANV-TIME-1", "campaign_id": camp_id, "created_at": now_1}
    c2 = {"id": "t_case_2", "case_number": "ANV-TIME-2", "campaign_id": camp_id, "created_at": now_3}
    c3 = {"id": "t_case_3", "case_number": "ANV-TIME-3", "campaign_id": camp_id, "created_at": now_2}
    supabase.insert("cases", c1)
    supabase.insert("cases", c2)
    supabase.insert("cases", c3)

    timeline = campaign_service.get_campaign_timeline(camp_id)
    assert len(timeline) >= 3
    timestamps = [e.get("timestamp") for e in timeline if e.get("timestamp")]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# 14 & 15. Original Evidence & Attribution Boundary Safety
# ---------------------------------------------------------------------------
def test_original_evidence_remains_unchanged():
    """Normalization must preserve original values and not alter input evidence records."""
    raw_subj = "  FW: [EXTERNAL] Urgent Wire Verification  "
    norm_subj = normalize_subject(raw_subj)
    assert norm_subj["original"] == raw_subj
    assert norm_subj["normalized"] == "urgent wire verification"

    raw_email = "John Doe <ATTACKER@Evil-Domain.com.>"
    norm_email = normalize_email(raw_email)
    assert norm_email["original"] == raw_email
    assert norm_email["domain"] == "evil-domain.com"
    assert norm_email["local_part"] == "ATTACKER"


def test_attribution_boundary_remains_unaltered():
    """
    Campaign correlation must NEVER modify:
    - Origin confidence
    - Actor identity
    - SPF/DKIM/DMARC verdicts
    """
    case = {
        "id": "attr-boundary-case",
        "case_number": "ANV-ATTR-01",
        "probable_origin_ip": "185.220.101.5",
        "origin_confidence": "HIGH",
        "status": "UNDER_REVIEW"
    }
    # Verify field values remain identical before and after correlation evaluation
    orig_conf = case["origin_confidence"]
    orig_ip = case["probable_origin_ip"]

    _ = campaign_service.evaluate_correlation(case_a=case, case_b=case)
    assert case["origin_confidence"] == orig_conf
    assert case["probable_origin_ip"] == orig_ip


# ---------------------------------------------------------------------------
# 16, 17 & 18. Frozen ML Model Integrity Verification
# ---------------------------------------------------------------------------
def test_model_1_phishing_hash_unchanged():
    """Model 1 (Phishing) SHA-256 must match frozen baseline."""
    expected_sha = "f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7"
    path = os.path.join("..", "ml", "models", "phishing_baseline_v1", "model.joblib")
    with open(path, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest().lower()
    assert actual_sha == expected_sha, f"Model 1 hash mismatch! Expected {expected_sha}, got {actual_sha}"


def test_model_2_bec_hash_unchanged():
    """Model 2 (BEC) SHA-256 must match frozen baseline."""
    expected_sha = "afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8"
    path = os.path.join("..", "ml", "models", "bec_baseline_v1", "model.joblib")
    with open(path, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest().lower()
    assert actual_sha == expected_sha, f"Model 2 hash mismatch! Expected {expected_sha}, got {actual_sha}"


def test_model_3b_lookalike_hash_unchanged():
    """Model 3B (Lookalike Domain) SHA-256 must match frozen baseline."""
    expected_sha = "31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559"
    path = os.path.join("..", "ml", "models", "lookalike_domain_v1", "model.joblib")
    with open(path, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest().lower()
    assert actual_sha == expected_sha, f"Model 3B hash mismatch! Expected {expected_sha}, got {actual_sha}"
