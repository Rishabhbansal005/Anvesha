"""
ANVESH Forensic Signal Fusion Engine (Phase 9B).
Synthesizes multi-modal technical evidence across:
- Content / NLP (Model 1 Phishing & Model 2 BEC)
- Identity & Header Impersonation (Model 3A)
- Lookalike Domain / Brand Deception (Model 3B)
- Cryptographic Authentication (SPF, DKIM, DMARC)
- Transport Trajectory (Received hops, origin confidence)
- Threat Intelligence (IP reputation, TOR/VPN traversal, RDAP)
- Campaign Intelligence (Observable clustering, correlation confidence)

Strict Governance Guarantees:
- ZERO MODEL RETRAINING: Preserves frozen Model 1, 2, 3A, and 3B outputs.
- ANTI-DOUBLE-COUNTING: Uses explicit independence groups to prevent overlapping observables from inflating scores.
- EXPLAINABLE CATEGORY SCORING: 0-100 score capped across 6 categories (no naive averaging).
- PRIMARY VS. SUPPORTING: Separates root deterministic findings from corroborating context.
- CONFLICT HANDLING: Explicitly detects and explains contradictions (e.g., Auth PASS on compromised accounts).
- ATTRIBUTION BOUNDARY: "Actor Identity: NOT ESTABLISHED" is an immutable invariant.
"""

import logging
import uuid
from typing import Dict, Any, List, Optional, Tuple
from app.core.constants import RiskLevel, get_risk_level_from_score
from app.schemas.fusion import (
    EvidenceContribution,
    EvidenceContradiction,
    CategoryBreakdownItem,
    FusionAttribution,
    ForensicFusionResult
)

logger = logging.getLogger(__name__)

# Category caps enforcing 100 maximum total score
CATEGORY_CAPS = {
    "CONTENT": 20,
    "IDENTITY": 20,
    "INFRASTRUCTURE": 20,
    "AUTHENTICATION": 15,
    "THREAT_INTEL": 15,
    "CAMPAIGN": 10
}

# Independence group maximum caps to avoid double-counting correlated evidence
INDEPENDENCE_GROUP_CAPS = {
    "DOMAIN_IDENTITY": 15,          # Lookalike domain vs sender domain mismatch
    "TRANSPORT_REPLY_TO": 15,       # Reply-to disparity
    "IDENTITY_AUTHORITY": 15,       # Executive freemail impersonation
    "CONTENT_PRESSURE": 15,         # BEC / Phish urgency language
    "CRYPTOGRAPHIC_AUTH": 15,       # SPF/DKIM/DMARC failures
    "INTEL_REPUTATION": 12,         # Malicious IP / ASN abuse
    "INTEL_PROXY": 8,               # TOR / VPN traversal
    "CAMPAIGN_CLUSTER": 10,         # Campaign association
    "TRANSPORT_ROUTING": 10,        # Hop anomalies
    "DISPOSABLE_PROVIDER": 8        # Disposable/temporary email provider (Phase 12.5)
}


class ForensicFusionService:
    """
    Consolidated, explainable forensic signal fusion service.
    """

    def fuse(
        self,
        ml_signal: Optional[Dict[str, Any]] = None,
        behavior_signal: Optional[Dict[str, Any]] = None,
        identity_impersonation: Optional[Dict[str, Any]] = None,
        lookalike_evidence: Optional[Dict[str, Any]] = None,
        auth_context: Optional[Dict[str, Any]] = None,
        transport_evidence: Optional[Dict[str, Any]] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
        campaign: Optional[Dict[str, Any]] = None,
        evidence_gaps: Optional[Dict[str, Any]] = None,
        disposable_evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes cross-modal evidence synthesis and returns structured ForensicFusionResult.
        """
        contributions: List[Dict[str, Any]] = []
        contradictions: List[Dict[str, Any]] = []
        primary_signals: List[str] = []
        supporting_signals: List[str] = []

        # Track score by independence group to enforce anti-double-counting
        group_totals: Dict[str, int] = {}

        def add_contribution(
            category: str,
            signal_name: str,
            severity: str,
            raw_pts: int,
            description: str,
            source: str,
            independence_group: str,
            is_primary: bool = False,
            parent_id: Optional[str] = None
        ):
            nonlocal contributions, primary_signals, supporting_signals, group_totals
            if raw_pts <= 0:
                return

            # Apply independence group cap to eliminate double counting
            allowed_group_cap = INDEPENDENCE_GROUP_CAPS.get(independence_group, 20)
            current_group_pts = group_totals.get(independence_group, 0)
            effective_pts = max(0, min(raw_pts, allowed_group_cap - current_group_pts))

            group_totals[independence_group] = current_group_pts + effective_pts

            ev_id = f"fus-evd-{uuid.uuid4().hex[:6]}"
            contrib = {
                "category": category,
                "signal": signal_name,
                "severity": severity,
                "contribution": effective_pts,
                "description": description,
                "source": source,
                "evidence_id": ev_id,
                "parent_evidence_id": parent_id,
                "independence_group": independence_group
            }
            contributions.append(contrib)

            if is_primary:
                if description not in primary_signals:
                    primary_signals.append(description)
            else:
                if description not in supporting_signals:
                    supporting_signals.append(description)

        # -------------------------------------------------------------
        # 1. CONTENT EVIDENCE (0 - 20)
        # -------------------------------------------------------------
        # A. Model 1 Phishing NLP
        ml = ml_signal or {}
        ml_score = ml.get("ml_score", 0)  # 0 - 30 scale
        if ml_score >= 15:
            factors = ml.get("ml_factors", [])
            factor_str = f" ({factors[0]})" if factors else ""
            add_contribution(
                category="CONTENT",
                signal_name="PHISHING_NLP_VECTOR",
                severity="HIGH" if ml_score >= 20 else "MEDIUM",
                raw_pts=min(12, int(round((ml_score / 30.0) * 12))),
                description=f"Model 1: Threat-oriented linguistic indicators detected{factor_str}.",
                source="MODEL_1",
                independence_group="CONTENT_PRESSURE",
                is_primary=False
            )

        # B. Model 2 BEC Urgency / Financial Coercion
        bec = behavior_signal or {}
        bec_score = bec.get("behavior_score", 0)
        bec_keywords = bec.get("bec_keywords", [])
        if bec_score >= 10 or bec_keywords:
            kw_desc = f" ('{bec_keywords[0]}')" if bec_keywords else ""
            add_contribution(
                category="CONTENT",
                signal_name="BEC_FINANCIAL_PRESSURE",
                severity="HIGH",
                raw_pts=12,
                description=f"Model 2: Financial coercion & urgency vector identified{kw_desc}.",
                source="MODEL_2",
                independence_group="CONTENT_PRESSURE",
                is_primary=True if bec_score >= 15 else False
            )

        # -------------------------------------------------------------
        # 2. IDENTITY EVIDENCE (0 - 20)
        # -------------------------------------------------------------
        m3a = identity_impersonation or {}
        m3a_signals = m3a.get("signals", [])
        m3a_score = m3a.get("identity_impersonation_score", 0)
        obs_identity = m3a.get("observed_identity", "Unknown")
        obs_sender = m3a.get("observed_sender", "Unknown")
        reply_to = m3a.get("reply_to")

        # Reply-To Mismatch
        if any(s.get("type") == "REPLY_TO_MISMATCH" for s in m3a_signals) or (reply_to and reply_to != obs_sender):
            add_contribution(
                category="IDENTITY",
                signal_name="REPLY_TO_MISMATCH",
                severity="HIGH",
                raw_pts=15,
                description=f"Reply-To address differs from observed sender (Claims: '{obs_sender}' -> Replies to: '{reply_to}').",
                source="MODEL_3A",
                independence_group="TRANSPORT_REPLY_TO",
                is_primary=True
            )

        # Executive / Freemail Deception
        if any(s.get("type") == "EXECUTIVE_EXTERNAL_DOMAIN" for s in m3a_signals):
            add_contribution(
                category="IDENTITY",
                signal_name="EXECUTIVE_FREEMAIL_IMPERSONATION",
                severity="HIGH",
                raw_pts=15,
                description=f"Executive authority display name ('{obs_identity}') originating from public freemail infrastructure.",
                source="MODEL_3A",
                independence_group="IDENTITY_AUTHORITY",
                is_primary=True
            )

        # Display Name Domain Mismatch
        if any(s.get("type") == "DISPLAY_NAME_DOMAIN_MISMATCH" for s in m3a_signals):
            add_contribution(
                category="IDENTITY",
                signal_name="DISPLAY_NAME_TRUSTED_MISMATCH",
                severity="HIGH",
                raw_pts=15,
                description=f"Observed display name '{obs_identity}' matches trusted profile but sender domain differs.",
                source="MODEL_3A",
                independence_group="DOMAIN_IDENTITY",
                is_primary=True
            )

        # Other M3A Signals
        for sig in m3a_signals:
            if sig.get("type") in ("SUSPICIOUS_SENDER_DOMAIN_RELATION", "DISPLAY_NAME_TRUSTED_DOMAIN_MISMATCH"):
                add_contribution(
                    category="IDENTITY",
                    signal_name=sig.get("type"),
                    severity="MEDIUM",
                    raw_pts=8,
                    description=sig.get("description", "Identity header inconsistency."),
                    source="MODEL_3A",
                    independence_group="DOMAIN_IDENTITY",
                    is_primary=False
                )

        # -------------------------------------------------------------
        # 3. INFRASTRUCTURE EVIDENCE (0 - 20)
        # -------------------------------------------------------------
        # A. Model 3B Lookalike Domain
        m3b = lookalike_evidence or {}
        m3b_signal = m3b.get("signal", "NONE")
        candidate_dom = m3b.get("candidate_domain", "")
        trusted_dom = m3b.get("trusted_domain", "")

        if m3b_signal in ("HIGH", "MEDIUM"):
            ind_list = m3b.get("deterministic_indicators", [])
            ind_text = f" [{', '.join(ind_list)}]" if ind_list else ""
            add_contribution(
                category="INFRASTRUCTURE",
                signal_name="LOOKALIKE_SENDER_DOMAIN",
                severity="HIGH" if m3b_signal == "HIGH" else "MEDIUM",
                raw_pts=15 if m3b_signal == "HIGH" else 8,
                description=f"Model 3B: Sender domain '{candidate_dom}' exhibits lookalike resemblance to trusted '{trusted_dom}'{ind_text}.",
                source="MODEL_3B",
                independence_group="DOMAIN_IDENTITY",  # Correlated with DOMAIN_IDENTITY
                is_primary=True if m3b_signal == "HIGH" else False
            )

        # B. Transport & Routing Telemetry
        trans = transport_evidence or {}
        origin_conf = trans.get("origin_confidence", "LOW")
        relay_count = trans.get("relay_count", 0)
        if relay_count > 6:
            add_contribution(
                category="INFRASTRUCTURE",
                signal_name="ANOMALOUS_RELAY_DEPTH",
                severity="MEDIUM",
                raw_pts=6,
                description=f"Anomalous SMTP trajectory depth ({relay_count} intermediary transit hops).",
                source="TRANSPORT_TRACER",
                independence_group="TRANSPORT_ROUTING",
                is_primary=False
            )

        # C. Disposable / Temporary Email Provider Intelligence (Phase 12.5)
        if hasattr(disposable_evidence, "model_dump"):
            disp = disposable_evidence.model_dump()
        elif hasattr(disposable_evidence, "dict"):
            disp = disposable_evidence.dict()
        elif isinstance(disposable_evidence, dict):
            disp = disposable_evidence
        else:
            disp = {}
        disp_class = str(disp.get("classification", "")).upper()
        if disp_class == "DISPOSABLE" or disp.get("is_disposable") is True:
            prov_name = disp.get("provider_name")
            prov_str = f" ({prov_name})" if prov_name else ""
            disp_dom = disp.get("domain", "")
            add_contribution(
                category="INFRASTRUCTURE",
                signal_name="DISPOSABLE_EMAIL_PROVIDER",
                severity="MEDIUM",
                raw_pts=8,
                description=f"Sender domain '{disp_dom}' is associated with a known disposable/temporary email provider{prov_str}.",
                source="DISPOSABLE_EMAIL_INTEL",
                independence_group="DISPOSABLE_PROVIDER",
                is_primary=False
            )

        # -------------------------------------------------------------
        # 4. AUTHENTICATION EVIDENCE (0 - 15)
        # -------------------------------------------------------------
        auth = auth_context or {}
        spf_status = str(auth.get("spf", "NOT OBSERVED")).upper()
        dkim_status = str(auth.get("dkim", "NOT OBSERVED")).upper()
        dmarc_status = str(auth.get("dmarc", "NOT OBSERVED")).upper()

        auth_failed = False
        if spf_status == "FAIL":
            auth_failed = True
            add_contribution(
                category="AUTHENTICATION",
                signal_name="SPF_VALIDATION_FAILURE",
                severity="HIGH",
                raw_pts=10,
                description="Sender Policy Framework (SPF) validation failed for sending host.",
                source="AUTH_VERIFIER",
                independence_group="CRYPTOGRAPHIC_AUTH",
                is_primary=True
            )
        if dkim_status == "FAIL":
            auth_failed = True
            add_contribution(
                category="AUTHENTICATION",
                signal_name="DKIM_SIGNATURE_FAILURE",
                severity="HIGH",
                raw_pts=8,
                description="DKIM asymmetric cryptographic signature verification failed.",
                source="AUTH_VERIFIER",
                independence_group="CRYPTOGRAPHIC_AUTH",
                is_primary=True
            )
        if dmarc_status == "FAIL":
            auth_failed = True
            add_contribution(
                category="AUTHENTICATION",
                signal_name="DMARC_POLICY_REJECT",
                severity="HIGH",
                raw_pts=8,
                description="Domain-based Message Authentication (DMARC) alignment policy check failed.",
                source="AUTH_VERIFIER",
                independence_group="CRYPTOGRAPHIC_AUTH",
                is_primary=True
            )

        # -------------------------------------------------------------
        # 5. THREAT INTELLIGENCE EVIDENCE (0 - 15)
        # -------------------------------------------------------------
        intel = threat_intel or {}
        rep_score = intel.get("reputation_score") or 0
        vpn_tor = intel.get("vpn_tor_proxy_indicator", "NONE")
        prob_ip = intel.get("ip_address") or intel.get("probable_origin_ip", "")

        if vpn_tor == "TOR_EXIT_RELAY":
            add_contribution(
                category="THREAT_INTEL",
                signal_name="TOR_EXIT_INFRASTRUCTURE",
                severity="HIGH",
                raw_pts=8,
                description=f"Origin gateway IP '{prob_ip}' associated with active TOR exit relay node.",
                source="THREAT_INTEL",
                independence_group="INTEL_PROXY",
                is_primary=True
            )
        elif vpn_tor in ("VPN_RELAY", "PROXY"):
            add_contribution(
                category="THREAT_INTEL",
                signal_name="ANONYMOUS_PROXY_TRAVERSAL",
                severity="MEDIUM",
                raw_pts=5,
                description=f"Message routed through commercial {vpn_tor.lower()} hosting infrastructure.",
                source="THREAT_INTEL",
                independence_group="INTEL_PROXY",
                is_primary=False
            )

        if rep_score >= 50:
            add_contribution(
                category="THREAT_INTEL",
                signal_name="MALICIOUS_IP_REPUTATION",
                severity="HIGH",
                raw_pts=12,
                description=f"Threat intelligence reports elevated abuse score ({rep_score}%) for origin IP '{prob_ip}'.",
                source="THREAT_INTEL",
                independence_group="INTEL_REPUTATION",
                is_primary=True
            )
        elif rep_score >= 25:
            add_contribution(
                category="THREAT_INTEL",
                signal_name="SUSPICIOUS_IP_REPUTATION",
                severity="MEDIUM",
                raw_pts=6,
                description=f"Threat intelligence reports suspicious abuse history ({rep_score}%) for origin gateway.",
                source="THREAT_INTEL",
                independence_group="INTEL_REPUTATION",
                is_primary=False
            )

        # -------------------------------------------------------------
        # 6. CAMPAIGN CORRELATION EVIDENCE (0 - 10)
        # -------------------------------------------------------------
        cmp = campaign or {}
        cmp_id = cmp.get("id") or cmp.get("campaign_id")
        cmp_conf = cmp.get("confidence")
        if cmp_id and cmp_conf:
            pts = 10 if cmp_conf == "HIGH" else (6 if cmp_conf == "MEDIUM" else 3)
            case_cnt = cmp.get("case_count", 2)
            add_contribution(
                category="CAMPAIGN",
                signal_name="CAMPAIGN_CORRELATION",
                severity="MEDIUM",
                raw_pts=pts,
                description=f"Correlated with potential coordinated campaign '{cmp_id}' ({cmp_conf} confidence, {case_cnt} related cases).",
                source="CAMPAIGN_ENGINE",
                independence_group="CAMPAIGN_CLUSTER",
                is_primary=False
            )

        # -------------------------------------------------------------
        # 7. CATEGORY SUMMATION & SCORE CALCULATION
        # -------------------------------------------------------------
        category_sums: Dict[str, int] = {cat: 0 for cat in CATEGORY_CAPS}
        for c in contributions:
            cat = c["category"]
            category_sums[cat] = category_sums.get(cat, 0) + c["contribution"]

        # Enforce category caps
        final_category_scores: Dict[str, CategoryBreakdownItem] = {}
        for cat, cap in CATEGORY_CAPS.items():
            final_category_scores[cat.lower()] = CategoryBreakdownItem(
                score=min(cap, category_sums.get(cat, 0)),
                max=cap
            )

        total_fusion_score = min(100, sum(item.score for item in final_category_scores.values()))
        risk_level_enum = get_risk_level_from_score(total_fusion_score)
        risk_level = risk_level_enum.value

        # -------------------------------------------------------------
        # 8. CONTRADICTION & CONFLICT DETECTION
        # -------------------------------------------------------------
        all_auth_pass = (spf_status == "PASS" and dkim_status == "PASS" and dmarc_status == "PASS")
        has_identity_threat = final_category_scores["identity"].score >= 10
        has_content_threat = final_category_scores["content"].score >= 10
        has_lookalike = m3b_signal in ("HIGH", "MEDIUM")

        # Conflict 1: Auth PASS but Identity / Behavioral threat
        if all_auth_pass and (has_identity_threat or has_content_threat or has_lookalike):
            contradictions.append({
                "type": "AUTH_PASS_BUT_IDENTITY_SUSPICIOUS",
                "description": "Cryptographic authentication passed (SPF/DKIM/DMARC: PASS), but identity impersonation and/or behavioral coercion signals remain elevated.",
                "conflicting_signals": [
                    f"SPF {spf_status}, DKIM {dkim_status}, DMARC {dmarc_status}",
                    f"Identity Risk: {final_category_scores['identity'].score}/20",
                    f"Content Risk: {final_category_scores['content'].score}/20"
                ],
                "resolution_note": "Authentication verification confirms sending server authorization only. Compromised corporate accounts, delegated relays, and lookalike domains with valid DNS records routinely pass SPF/DKIM."
            })

        # Conflict 2: Malicious IP but Benign Content
        has_bad_ip = rep_score >= 50 or vpn_tor == "TOR_EXIT_RELAY"
        if has_bad_ip and final_category_scores["content"].score == 0 and not has_identity_threat:
            contradictions.append({
                "type": "MALICIOUS_IP_BENIGN_CONTENT",
                "description": "Origin transport infrastructure is flagged by threat intelligence, but message content and identity headers exhibit no threat vectors.",
                "conflicting_signals": [
                    f"Threat Intel Risk: {final_category_scores['threat_intel'].score}/15",
                    "Content Risk: 0/20",
                    "Identity Risk: 0/20"
                ],
                "resolution_note": "Origin relay may be an uncompromised multi-tenant hop, an egress proxy, or historical reputation artifact. Preserve transport trajectory logs."
            })

        # Conflict 3: Cloud multi-tenant host with spoofed display name
        cloud_class = intel.get("cloud_classification", "")
        if cloud_class in ("MICROSOFT_365_OR_AZURE", "GOOGLE_WORKSPACE_OR_GCP") and has_identity_threat:
            contradictions.append({
                "type": "BENIGN_INFRASTRUCTURE_SUSPICIOUS_IDENTITY",
                "description": "Message traversed authentic enterprise cloud infrastructure, but exhibits executive display-name or Reply-To diversion.",
                "conflicting_signals": [
                    f"Hosting: {cloud_class}",
                    f"Identity Risk: {final_category_scores['identity'].score}/20"
                ],
                "resolution_note": "Threat actor utilized a legitimate SaaS subscription or compromised mailbox to execute executive spoofing. Invariant: Cloud hosting does NOT reduce identity risk."
            })

        # -------------------------------------------------------------
        # 9. FUSION CONFIDENCE DERIVATION
        # -------------------------------------------------------------
        # Count independent categories with non-trivial evidence
        active_categories = sum(1 for item in final_category_scores.values() if item.score >= 5)
        confidence_rationale = []

        if active_categories >= 3:
            fusion_confidence = "HIGH"
            confidence_rationale.append(f"Corroborated across {active_categories} independent evidence categories.")
        elif active_categories >= 2:
            fusion_confidence = "MEDIUM"
            confidence_rationale.append(f"Supported by {active_categories} evidence categories.")
        else:
            fusion_confidence = "LOW"
            confidence_rationale.append("Sparse evidence; assessment relies on isolated indicators.")

        if contradictions:
            confidence_rationale.append(f"Identified {len(contradictions)} technical contradiction(s) requiring analyst contextualization.")

        if not prob_ip or prob_ip == "NOT SPECIFIED":
            confidence_rationale.append("Origin IP not definitively established from RFC-822 Received chain.")

        # -------------------------------------------------------------
        # 10. DETERMINISTIC FORENSIC INTERPRETATION
        # -------------------------------------------------------------
        if total_fusion_score >= 70:
            interp_headline = f"High-confidence threat indicators detected ({total_fusion_score}/100)."
        elif total_fusion_score >= 40:
            interp_headline = f"Elevated forensic suspicion observed ({total_fusion_score}/100)."
        else:
            interp_headline = f"Low threat indicators observed across evaluated evidence ({total_fusion_score}/100)."

        if all_auth_pass and (has_identity_threat or has_content_threat or has_lookalike):
            interp_body = "Authentication passed, but identity and behavioral evidence remain suspicious. Authentication checks verify transport authorizations only and do not eliminate risk from compromised mailboxes or lookalike domains."
        elif auth_failed:
            interp_body = "Transport authorization failed cryptographic verification, corroborating potential sender spoofing or unauthorized relay traversal."
        else:
            interp_body = "Technical observables demonstrate consistent transport behavior with no immediate evidence of identity diversion."

        forensic_interpretation = f"{interp_headline} {interp_body}"

        # -------------------------------------------------------------
        # 11. STRUCTURED CONCLUSION RESULT
        # -------------------------------------------------------------
        return {
            "model": "anvesh_forensic_fusion_v1",
            "fusion_score": total_fusion_score,
            "risk_level": risk_level,
            "fusion_confidence": fusion_confidence,
            "confidence_rationale": confidence_rationale,
            "primary_signals": primary_signals[:5],
            "supporting_signals": supporting_signals[:5],
            "category_breakdown": {
                k: {"score": v.score, "max": v.max} for k, v in final_category_scores.items()
            },
            "contributions": contributions,
            "contradictions": contradictions,
            "forensic_interpretation": forensic_interpretation,
            "attribution": {
                "actor_identity": "NOT ESTABLISHED",
                "observed_infrastructure": intel.get("cloud_classification") or prob_ip or "Public Gateway",
                "origin_confidence": trans.get("origin_confidence") or "EVALUATED",
                "attribution_boundary": "Technical headers and forensic signal fusion establish transport trajectory, identity discrepancy, and infrastructure indicators only. Physical identity of the threat actor is NOT ESTABLISHED."
            },
            "evidence_gaps": evidence_gaps,
            "disclaimer": "Forensic Signal Fusion synthesizes technical observables and model evidence only. It does not establish attacker identity, legal liability, or actor intent."
        }


forensic_fusion_service = ForensicFusionService()
