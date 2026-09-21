"""
ANVESH Explainable ML Risk Scoring Engine.
Categorical score distribution (Total 0 - 100):
- ML Threat Risk: 0 - 30 (NLP semantic classification & behavioral vector analysis)
- Forensic / Auth Risk: 0 - 25 (SPF, DKIM, DMARC alignment & validation)
- Infrastructure Risk: 0 - 25 (Public relay traversal, AS reputation, gateway posture)
- Behavior / BEC Risk: 0 - 20 (Reply-To mismatch, display name spoofing, wire pressure)
"""
import re
import math
from typing import Dict, Any, List, Tuple, Optional
from app.core.constants import RiskLevel, get_risk_level_from_score


class MLThreatClassifier:
    """
    Lightweight, deterministic NLP semantic classifier for threat detection.
    Analyzes lexical entropy, BEC semantic patterns, and social engineering urgency vectors.
    """
    
    # Semantic token clusters with empirical weights
    BEC_FINANCIAL_TOKENS = {
        "wire transfer": 0.35,
        "swift": 0.25,
        "bank account": 0.25,
        "urgent payment": 0.30,
        "invoice overdue": 0.20,
        "confidential m&a": 0.35,
        "payroll direct deposit": 0.30,
        "gift card": 0.35,
        "routing number": 0.30,
        "remittance": 0.20,
        "beneficiary": 0.20,
        "fund transfer": 0.25,
    }

    CREDENTIAL_PHISH_TOKENS = {
        "verify your account": 0.30,
        "password expires": 0.35,
        "unauthorized login": 0.25,
        "suspended temporarily": 0.30,
        "click here to confirm": 0.25,
        "security notice": 0.15,
        "reset your credentials": 0.35,
        "update billing information": 0.30,
    }

    URGENCY_PRESSURE_TOKENS = {
        "immediately": 0.15,
        "urgent": 0.15,
        "action required": 0.15,
        "within 24 hours": 0.20,
        "do not delay": 0.20,
        "strictly confidential": 0.20,
        "executive priority": 0.25,
    }

    # Consumer & Enterprise Phishing Lures (Ingested from modern benchmark corpora)
    CONSUMER_PHISHING_LURES = {
        "gift card": 0.35,
        "claim your prize": 0.35,
        "won a": 0.30,
        "package delivery": 0.35,
        "confirm delivery": 0.30,
        "unusual login attempt": 0.35,
        "account has been compromised": 0.40,
        "payment has been declined": 0.35,
        "subscription is about to expire": 0.30,
        "update your billing information": 0.30,
        "update your email account settings": 0.30,
        "secure message from your bank": 0.35,
        "unusual activity in your account": 0.30,
        "invoice is attached": 0.25,
        "click here to claim": 0.35,
        "click the link to reset": 0.35,
        "avoid penalties": 0.25,
        "avoid service interruption": 0.30,
        "nfo": 0.35,
        "new fund offer": 0.35,
        "investment opportunity": 0.35,
        "invest now": 0.30,
        "mutual fund": 0.30,
        "pre-approved": 0.35,
        "credit card approved": 0.35,
        "guaranteed returns": 0.40,
        "exclusive offer": 0.25,
        "worth exploring": 0.30,
        "click here": 0.25,
        "apply now": 0.25
    }

    SUSPICIOUS_TLDS = {
        ".top", ".xyz", ".club", ".work", ".click", ".buzz", ".cam", ".rest", ".tk", ".ml"
    }

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Calculates Shannon entropy to detect algorithmically generated domains or obfuscation."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])

    @classmethod
    def classify(cls, text: str, sender: str = "", subject: str = "") -> Dict[str, Any]:
        combined_text = f"{subject} {text}".lower()
        ml_factors: List[str] = []
        raw_score = 0.0

        # 1. BEC Financial Vector Analysis
        bec_hits = []
        for token, weight in cls.BEC_FINANCIAL_TOKENS.items():
            if token in combined_text:
                bec_hits.append(token)
                raw_score += weight

        if bec_hits:
            ml_factors.append(f"ML identified financial coercion vector: {', '.join(bec_hits[:3])}")

        # 2. Credential Phishing Vector Analysis
        phish_hits = []
        for token, weight in cls.CREDENTIAL_PHISH_TOKENS.items():
            if token in combined_text:
                phish_hits.append(token)
                raw_score += weight

        if phish_hits:
            ml_factors.append(f"ML identified credential harvesting pattern: {', '.join(phish_hits[:2])}")

        # 3. Consumer Phishing & Social Engineering Lures
        lure_hits = []
        for token, weight in cls.CONSUMER_PHISHING_LURES.items():
            if token in combined_text:
                lure_hits.append(token)
                raw_score += weight

        if lure_hits:
            ml_factors.append(f"ML identified social engineering lure: {', '.join(lure_hits[:2])}")

        # 4. Urgency & Social Engineering Vector
        urgency_hits = []
        for token, weight in cls.URGENCY_PRESSURE_TOKENS.items():
            if token in combined_text:
                urgency_hits.append(token)
                raw_score += weight

        if urgency_hits:
            ml_factors.append(f"Psychological urgency triggers observed: {', '.join(urgency_hits[:2])}")

        # 5. Hyperlink and IP Destination Analysis
        if re.search(r"https?://", combined_text):
            raw_score += 0.20
            ml_factors.append("Embedded external hyperlink detected")
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", combined_text):
                raw_score += 0.35
                ml_factors.append("Direct raw IP destination URL detected (evasion indicator)")
            if re.search(r"/(?:r|track|click|redirect|goto|lnk)/\?|\b(?:id=|p1=|token=|track=)", combined_text) or "%40" in combined_text:
                raw_score += 0.35
                ml_factors.append("Opaque click-tracking redirect URL detected (marketing/phishing tracking vector)")

        # 6. Domain & Sender Lexical Analysis
        sender_lower = sender.lower()
        for tld in cls.SUSPICIOUS_TLDS:
            if tld in sender_lower:
                raw_score += 0.30
                ml_factors.append(f"Sender domain utilizes high-abuse TLD ({tld})")
                break

        # Check sender display name vs address disparity (Executive Impersonation & Brand Divergence)
        if '"' in sender or "'" in sender or "<" in sender:
            display_name = sender.split("<")[0].strip(' "\'')
            address_part = sender.split("<")[-1].strip(' >') if "<" in sender else sender
            
            exec_keywords = ["ceo", "cfo", "director", "president", "dr.", "executive", "admin", "it support"]
            if any(k in display_name.lower() for k in exec_keywords):
                if any(freemail in address_part.lower() for freemail in ["gmail.com", "protonmail.com", "yahoo.com", "outlook.com", "hotmail.com"]):
                    raw_score += 0.45
                    ml_factors.append(f"Executive display name spoofing detected ('{display_name}' on public freemail provider)")

            brand_keywords = ["bank", "hdfc", "sbi", "icici", "axis", "chase", "paypal", "microsoft", "apple", "amazon", "netflix", "fedex", "dhl", "ups"]
            if any(b in display_name.lower() for b in brand_keywords):
                domain_part = address_part.split("@")[-1].lower() if "@" in address_part else address_part.lower()
                if "mailers." in domain_part or "promo" in domain_part or domain_part.count(".") >= 3:
                    raw_score += 0.40
                    ml_factors.append(f"Institutional brand display name '{display_name}' divergence on multi-tier bulk mailer ('{domain_part}')")

        if "list-unsubscribe" in combined_text or "to unsubscribe" in combined_text or "opt out" in combined_text:
            raw_score += 0.25
            ml_factors.append("Unsolicited bulk marketing / mass-mailer signature observed (high spam propensity)")

        # 7. Model 1 Statistical TF-IDF Inference Fusion
        try:
            from ml.inference.predictor import PhishingPredictor
            predictor = PhishingPredictor()
            pred_res = predictor.predict_email(subject, text)
            pred_proba = float(pred_res.get("phishing_probability", 0.0))
            if pred_proba >= 0.50:
                raw_score = max(raw_score, pred_proba)
                ml_factors.append(f"Statistically validated by Model 1 TF-IDF classifier ({pred_proba * 100:.1f}% confidence)")
        except Exception:
            pass

        # Normalize ML probability to 0.0 - 1.0
        ml_probability = min(1.0, raw_score)
        
        # Scale to ML weight category (0 - 20)
        ml_score = int(round(ml_probability * 20))

        return {
            "ml_score": ml_score,
            "ml_probability": round(ml_probability, 3),
            "ml_factors": ml_factors,
            "model_identifier": "ANVESH-NLP-Vector-v2.1"
        }


class RiskEngine:
    """
    Consolidated, transparent risk evaluation engine.
    Ensures that every risk point is explainable and attributed to a category.
    Total maximum points across all 6 models sum to exactly 100:
    - ML Phishing NLP: 20
    - Cryptographic Auth: 20
    - Transport Infrastructure: 20
    - Behavioral / BEC: 20
    - Lookalike Domain: 10
    - Identity Impersonation: 10
    """
    @staticmethod
    def calculate_risk(
        ml_score: int = 0,             # 0 - 20
        auth_risk: int = 0,            # 0 - 20
        infra_risk: int = 0,           # 0 - 20
        behavior_bec_risk: int = 0,    # 0 - 20
        lookalike_risk: int = 0,       # 0 - 10 (Model 3B Lookalike Evidence)
        identity_risk: int = 0,        # 0 - 10 (Model 3A Identity Impersonation Evidence)
        reasons: List[str] = None,
        disposable_risk: int = 0       # 0 - 5 (Phase 12.5 Disposable Provider Evidence)
    ) -> Dict[str, Any]:
        ml_score = max(0, min(20, ml_score))
        auth_risk = max(0, min(20, auth_risk))
        infra_risk = max(0, min(20, infra_risk))
        behavior_bec_risk = max(0, min(20, behavior_bec_risk))
        lookalike_risk = max(0, min(10, lookalike_risk))
        identity_risk = max(0, min(10, identity_risk))
        disposable_risk = max(0, min(5, disposable_risk))
        
        # Transparent, explainable score directly equal to the exact sum of all model category scores (Max = 100)
        total_score = min(100, max(0, ml_score + auth_risk + infra_risk + behavior_bec_risk + lookalike_risk + identity_risk + disposable_risk))
            
        level = get_risk_level_from_score(total_score)
        
        cat_scores = {
            "ml_risk": {"score": ml_score, "max": 20},
            "forensic_auth_risk": {"score": auth_risk, "max": 20},
            "infrastructure_risk": {"score": infra_risk, "max": 20},
            "behavior_bec_risk": {"score": behavior_bec_risk, "max": 20},
            "lookalike_impersonation_risk": {"score": lookalike_risk, "max": 10},
            "identity_impersonation_risk": {"score": identity_risk, "max": 10}
        }
        if disposable_risk > 0:
            cat_scores["disposable_email_risk"] = {"score": disposable_risk, "max": 5}

        return {
            "risk_score": total_score,
            "risk_level": level.value,
            "category_scores": cat_scores,
            "reasons": reasons or [],
            "is_explainable": True
        }

    @staticmethod
    def evaluate_disposable_email_risk(disposable_result: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
        """
        Calculates disposable email provider risk contribution (0 - 8) based strictly on provider intelligence.
        Guarantees:
        - Disposable email is NOT proof of malicious activity (bounded supporting context only).
        - Privacy / Forwarding services receive strictly 0 risk contribution.
        - NEVER asserts attacker identity.
        """
        if not disposable_result:
            return 0, []

        if isinstance(disposable_result, str):
            from app.services.disposable_email_service import disposable_email_service
            disp_obj = disposable_email_service.classify_sender(disposable_result)
            disposable_result = disp_obj.model_dump()
        elif hasattr(disposable_result, "model_dump"):
            disposable_result = disposable_result.model_dump()
        elif hasattr(disposable_result, "dict"):
            disposable_result = disposable_result.dict()

        classification = str(disposable_result.get("classification", "UNKNOWN")).upper()
        if "DISPOSABLE" in classification or disposable_result.get("is_disposable") is True:
            provider = disposable_result.get("provider_name")
            prov_text = f" ({provider})" if provider else ""
            return 8, [f"Sender domain is associated with a known disposable/temporary email provider{prov_text}"]

        return 0, []

    @staticmethod
    def evaluate_infrastructure_risk(
        vpn_tor_proxy_indicator: str = "NONE",
        threat_verdict: str = "UNKNOWN",
        abuse_score: Optional[int] = None,
        is_cloud_provider: bool = False
    ) -> Tuple[int, List[str]]:
        """
        Calculates infrastructure risk contribution (0 - 25) based strictly on observed indicators.
        Guarantees:
        - VPN/TOR indicator alone does not make email critical (capped at +8 points).
        - Clean infrastructure does not reduce behavioral/BEC risk.
        """
        score = 0
        reasons = []

        if vpn_tor_proxy_indicator == "TOR_EXIT_RELAY":
            score += 8
            reasons.append("Observed infrastructure associated with a known TOR exit relay")
        elif vpn_tor_proxy_indicator in ("VPN_RELAY", "PROXY"):
            score += 5
            reasons.append(f"Infrastructure indicates {vpn_tor_proxy_indicator.lower()} traversal")

        abuse_val = 0
        if abuse_score is not None:
            try:
                abuse_val = float(abuse_score)
            except (ValueError, TypeError):
                abuse_val = 0

        if threat_verdict == "MALICIOUS" or abuse_val >= 75:
            score += 12
            reasons.append(f"Threat intelligence flagged relay IP as known malicious infrastructure ({int(abuse_val)}% abuse confidence)")
        elif threat_verdict == "SUSPICIOUS" or abuse_val >= 30:
            score += 8
            reasons.append(f"Threat intelligence reports elevated abuse confidence score ({int(abuse_val)}%)")

        return min(20, score), reasons



    @staticmethod
    def evaluate_lookalike_risk(lookalike_result: Dict[str, Any]) -> Tuple[int, List[str]]:
        """
        Calculates lookalike / brand impersonation risk contribution (0 - 10) based strictly on Model 3B evidence.
        Guarantees:
        - Domain evidence indicates infrastructure similarity only.
        - NEVER asserts or establishes actor identity.
        """
        score = 0
        reasons = []
        signal = lookalike_result.get("signal", "NONE")
        indicators = lookalike_result.get("deterministic_indicators", [])
        trusted = lookalike_result.get("trusted_domain", "unspecified")
        candidate = lookalike_result.get("candidate_domain", "unspecified")

        if signal == "HIGH":
            score = 10
            ind_desc = ", ".join(indicators) if indicators else "Structural typosquat resemblance"
            reasons.append(
                f"LOOKALIKE DOMAIN SIGNAL: HIGH - Observed indicator: {ind_desc}. "
                f"Candidate '{candidate}' resembles trusted '{trusted}'. "
                f"Infrastructure/domain evidence only."
            )
        elif signal == "MEDIUM":
            score = 5
            reasons.append(
                f"LOOKALIKE DOMAIN SIGNAL: MEDIUM - Candidate '{candidate}' exhibits lexical proximity to trusted '{trusted}'. "
                f"Infrastructure/domain evidence only."
            )

        return min(10, score), reasons

    @staticmethod
    def evaluate_identity_risk(identity_result: Dict[str, Any]) -> Tuple[int, List[str]]:
        """
        Calculates identity impersonation risk contribution (0 - 10) based strictly on Model 3A evidence.
        Guarantees:
        - Evidence/correlation signal only.
        - NEVER asserts or establishes actor identity (Actor Identity: NOT ESTABLISHED).
        """
        score = 0
        reasons = []
        impersonation_score = identity_result.get("identity_impersonation_score", 0)
        confidence = identity_result.get("confidence", "NONE")
        obs_identity = identity_result.get("observed_identity", "Unknown")
        obs_sender = identity_result.get("observed_sender", "Unknown")
        trusted = identity_result.get("trusted_identity")

        # Scale 0-100 score to 0-10 risk contribution
        if impersonation_score > 0:
            score = min(10, int(round((impersonation_score / 100.0) * 10)))

        signals = identity_result.get("signals", [])
        if signals:
            top_descriptions = [s.get("description", "") for s in signals[:2] if s.get("description")]
            trusted_clause = f" (resembling trusted '{trusted}')" if trusted else ""
            desc_str = "; ".join(top_descriptions)
            reasons.append(
                f"IDENTITY IMPERSONATION SIGNAL: {confidence} ({impersonation_score}/100) - "
                f"Observed '{obs_identity}' <{obs_sender}>{trusted_clause}. Indicators: {desc_str}. "
                f"Actor Identity: NOT ESTABLISHED."
            )

        return min(10, score), reasons


risk_engine = RiskEngine()
ml_classifier = MLThreatClassifier()
