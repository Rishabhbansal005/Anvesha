"""
ANVESH Model 3A Standalone Inference Predictor.
Governed Deterministic Baseline for Email Identity & Header Impersonation Detection.

Core Responsibilities:
- Executive display-name impersonation detection
- Supplier / vendor identity impersonation detection
- Sender address vs. display-name mismatch detection
- Reply-To identity mismatch analysis
- Header identity inconsistencies analysis
- Known/trusted identity vs. observed sender mismatch
- Synergistic integration with Model 3B (lookalike domain evidence)

Governance Guarantees:
- EVIDENCE / CORRELATION ENGINE ONLY
- NEVER claims a real person committed the attack
- NEVER identifies an attacker
- NEVER converts an impersonation signal into actor attribution
- MANDATORY ATTRIBUTION BOUNDARY: "Actor Identity: NOT ESTABLISHED"
- Uncalibrated explainable score (0-100), NEVER called probability
- Authentication PASS does NOT eliminate or suppress identity signals
"""

import re
from email.utils import parseaddr
from typing import Dict, Any, List, Optional, Tuple

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "protonmail.com", "proton.me",
    "icloud.com", "me.com", "aol.com", "zoho.com", "mail.com", "gmx.com",
    "yandex.com", "tutanota.com", "fastmail.com"
}

EXECUTIVE_TITLES = [
    "ceo", "cfo", "coo", "cto", "cio", "ciso", "cro", "chief executive",
    "chief financial", "chief operating", "chief technology", "president",
    "vice president", "vp", "director", "managing director", "treasury",
    "finance director", "head of finance", "payroll", "board of directors",
    "general counsel", "executive director"
]


class IdentityImpersonationPredictor:
    """
    Governed deterministic evidence predictor for Model 3A.
    Computes explainable identity impersonation score (0-100).
    """

    def __init__(self):
        self.model_version = "model3a_deterministic_v1"
        self.status = "GOVERNED_BASELINE"

    @staticmethod
    def extract_address_components(address_str: str) -> Tuple[str, str, str, str]:
        """
        Extracts (display_name, full_address, local_part, domain).
        Uses RFC-822 parseaddr with defensive fallbacks.
        """
        if not address_str:
            return "", "", "", ""
        
        name, addr = parseaddr(address_str.strip())
        addr_clean = addr.lower().strip()
        local_part = ""
        domain = ""
        if "@" in addr_clean:
            parts = addr_clean.split("@", 1)
            local_part = parts[0].strip()
            domain = parts[1].strip(" >\t\r\n")

        # Clean display name quotes
        name_clean = name.strip(' "\'').strip()
        return name_clean, addr_clean, local_part, domain

    def predict(
        self,
        sender_header: str,
        reply_to_header: Optional[str] = None,
        trusted_identity: Optional[Dict[str, Any]] = None,
        model3b_result: Optional[Dict[str, Any]] = None,
        auth_context: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates email headers for identity impersonation evidence.
        """
        obs_display, obs_addr, obs_local, obs_domain = self.extract_address_components(sender_header)
        reply_display, reply_addr, reply_local, reply_domain = self.extract_address_components(reply_to_header or "")

        signals: List[Dict[str, Any]] = []
        raw_score = 0
        score_breakdown: List[Dict[str, Any]] = []

        auth = auth_context or {"spf": "NOT OBSERVED", "dkim": "NOT OBSERVED", "dmarc": "NOT OBSERVED"}
        spf_status = (auth.get("spf") or "NOT OBSERVED").upper()
        dkim_status = (auth.get("dkim") or "NOT OBSERVED").upper()
        dmarc_status = (auth.get("dmarc") or "NOT OBSERVED").upper()

        # -------------------------------------------------------------
        # SIGNAL 1: DISPLAY NAME / TRUSTED IDENTITY MISMATCH (+30)
        # -------------------------------------------------------------
        trusted_name = (trusted_identity.get("display_name") or "").strip() if trusted_identity else ""
        trusted_email = (trusted_identity.get("email") or "").lower().strip() if trusted_identity else ""
        trusted_domain = (trusted_identity.get("domain") or "").lower().strip() if trusted_identity else ""
        if not trusted_domain and "@" in trusted_email:
            trusted_domain = trusted_email.split("@")[-1]

        if trusted_identity and (trusted_name or trusted_email):
            name_match = (
                (trusted_name and obs_display and trusted_name.lower() in obs_display.lower())
                or (trusted_email and trusted_email in obs_display.lower())
            )
            domain_mismatch = trusted_domain and obs_domain and (trusted_domain != obs_domain)

            if name_match and domain_mismatch:
                pts = 30
                raw_score += pts
                signals.append({
                    "type": "DISPLAY_NAME_DOMAIN_MISMATCH",
                    "severity": "HIGH",
                    "points": pts,
                    "description": f"Observed display name '{obs_display}' matches trusted identity '{trusted_name}', but observed sender domain '{obs_domain}' differs from trusted domain '{trusted_domain}'."
                })
                score_breakdown.append({"rule": "Display-name trusted-identity mismatch", "points": pts})

        # -------------------------------------------------------------
        # SIGNAL 2: EXECUTIVE DISPLAY NAME + EXTERNAL / FREEMAIL DOMAIN (+25)
        # -------------------------------------------------------------
        is_exec_name = False
        display_lower = obs_display.lower()
        for title in EXECUTIVE_TITLES:
            if re.search(r'\b' + re.escape(title) + r'\b', display_lower):
                is_exec_name = True
                break

        # Also consider trusted identity marked as EXECUTIVE
        if trusted_identity and trusted_identity.get("identity_type") in ("EXECUTIVE", "OFFICER", "LEADERSHIP"):
            if trusted_name and obs_display and trusted_name.lower() in display_lower:
                is_exec_name = True

        if is_exec_name:
            if obs_domain in FREEMAIL_DOMAINS:
                pts = 25
                raw_score += pts
                signals.append({
                    "type": "EXECUTIVE_EXTERNAL_DOMAIN",
                    "severity": "HIGH",
                    "points": pts,
                    "description": f"Executive authority indicator ('{obs_display}') observed originating from public freemail infrastructure ('{obs_domain}')."
                })
                score_breakdown.append({"rule": "Executive display name on public freemail provider", "points": pts})
            elif trusted_domain and obs_domain and obs_domain != trusted_domain:
                # Executive from external domain not in freemail
                # Already captured by signal 1 if trusted_identity matched, but add if distinct
                if not any(s["type"] == "DISPLAY_NAME_DOMAIN_MISMATCH" for s in signals):
                    pts = 25
                    raw_score += pts
                    signals.append({
                        "type": "EXECUTIVE_EXTERNAL_DOMAIN",
                        "severity": "HIGH",
                        "points": pts,
                        "description": f"Executive identity ('{obs_display}') observed from non-corporate external domain ('{obs_domain}')."
                    })
                    score_breakdown.append({"rule": "External-domain executive impersonation", "points": pts})

        # -------------------------------------------------------------
        # SIGNAL 3: SENDER ADDRESS / LOCAL-PART DISPARITY (+15)
        # -------------------------------------------------------------
        # Observed display name contains a specific person name, but sender local-part is unrelated or generic
        if obs_display and obs_local:
            display_words = [w for w in re.findall(r'[a-zA-Z]{3,}', obs_display.lower()) if w not in EXECUTIVE_TITLES]
            generic_local_parts = {"billing", "payments", "invoicing", "accounts", "support", "helpdesk", "secure", "alert", "wire", "remit"}
            
            # If display name has personal names but local part is generic or completely unrelated on an external domain
            has_personal_name = len(display_words) >= 2
            is_generic_local = any(g in obs_local for g in generic_local_parts)
            
            if has_personal_name and is_generic_local and (obs_domain in FREEMAIL_DOMAINS or (trusted_domain and obs_domain != trusted_domain)):
                pts = 15
                raw_score += pts
                signals.append({
                    "type": "SUSPICIOUS_SENDER_DOMAIN_RELATION",
                    "severity": "MEDIUM",
                    "points": pts,
                    "description": f"Personal display name '{obs_display}' conflicts with generic operational mailbox '{obs_local}@{obs_domain}'."
                })
                score_breakdown.append({"rule": "Personal display name paired with generic sender address", "points": pts})

        # -------------------------------------------------------------
        # SIGNAL 4: REPLY-TO IDENTITY MISMATCH (+25)
        # -------------------------------------------------------------
        if reply_addr and obs_addr and (reply_addr != obs_addr):
            pts = 25
            raw_score += pts
            signals.append({
                "type": "REPLY_TO_MISMATCH",
                "severity": "HIGH",
                "points": pts,
                "description": f"Reply-To address '{reply_addr}' differs from observed sender '{obs_addr}'."
            })
            score_breakdown.append({"rule": "Reply-To identity differs from observed sender", "points": pts})

        # -------------------------------------------------------------
        # SIGNAL 5: DISPLAY NAME / TRUSTED DOMAIN MISMATCH (+15)
        # -------------------------------------------------------------
        # e.g. Display name says "Company Support" or includes trusted brand, but domain is external
        if trusted_domain and trusted_domain in display_lower and obs_domain != trusted_domain:
            if not any(s["type"] in ("DISPLAY_NAME_DOMAIN_MISMATCH", "EXECUTIVE_EXTERNAL_DOMAIN") for s in signals):
                pts = 15
                raw_score += pts
                signals.append({
                    "type": "DISPLAY_NAME_TRUSTED_DOMAIN_MISMATCH",
                    "severity": "MEDIUM",
                    "points": pts,
                    "description": f"Display name '{obs_display}' references trusted organization '{trusted_domain}', but sender domain is '{obs_domain}'."
                })
                score_breakdown.append({"rule": "Display name references trusted domain from external sender", "points": pts})

        # -------------------------------------------------------------
        # SIGNAL 6: MODEL 3B LOOKALIKE SUPPORT (+15)
        # -------------------------------------------------------------
        m3b_signal = "NONE"
        if model3b_result:
            m3b_signal = model3b_result.get("signal", "NONE")
            m3b_trusted = model3b_result.get("trusted_domain", "")
            if m3b_signal in ("HIGH", "MEDIUM"):
                pts = 15
                raw_score += pts
                signals.append({
                    "type": "MODEL3B_LOOKALIKE_SUPPORT",
                    "severity": "HIGH" if m3b_signal == "HIGH" else "MEDIUM",
                    "points": pts,
                    "description": f"Identity impersonation evidence is strengthened by Model 3B lookalike sender domain ('{obs_domain}' resembles '{m3b_trusted}')."
                })
                score_breakdown.append({"rule": "Sender domain has lookalike relationship (Model 3B)", "points": pts})

        # -------------------------------------------------------------
        # SIGNAL 7: AUTHENTICATION FAILURE CONTEXT (+10)
        # -------------------------------------------------------------
        has_auth_fail = (spf_status == "FAIL" or dkim_status == "FAIL" or dmarc_status == "FAIL")
        if has_auth_fail:
            pts = 10
            raw_score += pts
            failed_protocols = [p for p, s in [("SPF", spf_status), ("DKIM", dkim_status), ("DMARC", dmarc_status)] if s == "FAIL"]
            signals.append({
                "type": "AUTH_FAILURE_CONTEXT",
                "severity": "MEDIUM",
                "points": pts,
                "description": f"Cryptographic authentication failure ({', '.join(failed_protocols)}) elevates identity deception risk."
            })
            score_breakdown.append({"rule": "Authentication failure context", "points": pts})

        # Score normalization & cap
        final_score = min(100, max(0, raw_score))

        # Confidence categorization
        if final_score >= 70:
            confidence = "HIGH"
        elif final_score >= 40:
            confidence = "MEDIUM"
        elif final_score > 0:
            confidence = "LOW"
        else:
            confidence = "NONE"

        detected = final_score >= 40

        # Construct trusted identity string if available
        trusted_repr = None
        if trusted_identity:
            if trusted_name and trusted_email:
                trusted_repr = f"{trusted_name} <{trusted_email}>"
            elif trusted_email:
                trusted_repr = trusted_email
            elif trusted_name:
                trusted_repr = trusted_name

        # Explicit compromised-account reminder when authentication passes but signals remain
        all_auth_pass = (spf_status == "PASS" and dkim_status == "PASS" and dmarc_status == "PASS")
        auth_disclaimer = None
        if all_auth_pass and detected:
            auth_disclaimer = "Authentication passed (SPF/DKIM/DMARC PASS), but identity impersonation indicators remain. Possible mailbox compromise or external lookalike infrastructure."

        return {
            "model": "model3a_deterministic_v1",
            "identity_impersonation_detected": detected,
            "identity_impersonation_score": final_score,
            "confidence": confidence,
            "observed_identity": obs_display or "NOT SPECIFIED",
            "observed_sender": obs_addr or "NOT SPECIFIED",
            "observed_local_part": obs_local,
            "observed_domain": obs_domain,
            "reply_to": reply_addr or None,
            "trusted_identity": trusted_repr,
            "signals": signals,
            "score_breakdown": score_breakdown,
            "authentication_context": {
                "spf": spf_status,
                "dkim": dkim_status,
                "dmarc": dmarc_status,
                "all_pass": all_auth_pass,
                "disclaimer": auth_disclaimer
            },
            "attribution": {
                "actor_identity": "NOT ESTABLISHED",
                "attribution_boundary": "Technical headers and display-name analysis establish identity discrepancy evidence only. Physical identity of the threat actor is NOT ESTABLISHED."
            },
            "disclaimer": "Identity Impersonation Signal reflects evidence of mismatch and social engineering heuristics. It does not establish attacker identity or legal liability."
        }


# Global singleton instance
_predictor_instance = None

def get_identity_impersonation_predictor() -> IdentityImpersonationPredictor:
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = IdentityImpersonationPredictor()
    return _predictor_instance
