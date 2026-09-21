"""
ANVESH Backend Lookalike Domain Evidence Service.
Integrates Model 3B (lookalike_domain_v1) into ANVESH email investigation pipelines.
Enforces defense-in-depth:
Tier 1 Deterministic Security Invariants -> Tier 2 Random Forest Structural Model.
"""

import logging
from typing import Dict, Any, List, Optional
import sys
from pathlib import Path

# Ensure repository root is on sys.path when running from backend directory
_repo_root = str(Path(__file__).resolve().parent.parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from ml.inference.lookalike_predictor import get_lookalike_predictor, LookalikePredictor

logger = logging.getLogger(__name__)

# Curated registry of high-profile target brands/domains often targeted in BEC/Phishing
CURATED_TARGET_REGISTRY = {
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "google.com": "Google",
    "paypal.com": "PayPal",
    "amazon.com": "Amazon",
    "chase.com": "Chase",
    "bankofamerica.com": "Bank of America",
    "wellsfargo.com": "Wells Fargo",
    "docusign.com": "DocuSign",
    "dropbox.com": "Dropbox",
    "adobe.com": "Adobe",
    "salesforce.com": "Salesforce",
    "intuit.com": "Intuit",
    "quickbooks.com": "QuickBooks",
    "linkedin.com": "LinkedIn",
    "zoom.us": "Zoom",
    "stripe.com": "Stripe",
    "binance.com": "Binance",
    "coinbase.com": "Coinbase",
    "fedex.com": "FedEx",
    "dhl.com": "DHL",
    "ups.com": "UPS"
}


class LookalikeService:
    def __init__(self):
        try:
            self.predictor = get_lookalike_predictor()
            self.available = True
        except Exception as e:
            logger.error(f"LookalikeService initialization failed: {e}")
            self.predictor = None
            self.available = False

    def detect_lookalike(self, candidate_domain: str, trusted_domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluate candidate domain against a trusted domain or identify closest target from curated registry.
        """
        if not self.available or self.predictor is None:
            return {
                "model": "lookalike_domain_v1",
                "signal": "UNKNOWN",
                "raw_model_score": 0.0,
                "deterministic_indicators": ["SERVICE_UNAVAILABLE"],
                "features": {},
                "explanation": ["Model 3B predictor is unavailable or failed integrity verification."],
                "model_status": "UNAVAILABLE"
            }

        candidate_clean = candidate_domain.lower().strip()

        # If trusted domain is explicitly specified, evaluate directly
        if trusted_domain:
            res = self.predictor.predict(trusted_domain, candidate_clean)
            res["candidate_domain"] = candidate_clean
            res["trusted_domain"] = trusted_domain.lower().strip()
            return res

        # Otherwise, scan curated target registry to find the highest threat lookalike match
        highest_signal_result = None
        max_score = -1.0

        for target_dom, brand in CURATED_TARGET_REGISTRY.items():
            result = self.predictor.predict(target_dom, candidate_clean)
            # If deterministic indicator triggered or higher score found
            if result["deterministic_indicators"] and "AUTHENTIC_DOMAIN" not in result["deterministic_indicators"]:
                result["candidate_domain"] = candidate_clean
                result["trusted_domain"] = target_dom
                result["target_brand"] = brand
                return result

            if result["raw_model_score"] > max_score:
                max_score = result["raw_model_score"]
                result["candidate_domain"] = candidate_clean
                result["trusted_domain"] = target_dom
                result["target_brand"] = brand
                highest_signal_result = result

        if highest_signal_result and highest_signal_result["signal"] in ("HIGH", "MEDIUM"):
            return highest_signal_result

        # Default clean / authentic result
        return {
            "model": "lookalike_domain_v1",
            "candidate_domain": candidate_clean,
            "trusted_domain": trusted_domain or "Not Identified",
            "signal": "NONE",
            "raw_model_score": 0.0,
            "deterministic_indicators": ["NO_LOOKALIKE_DETECTED"],
            "features": {},
            "explanation": ["Candidate domain does not exhibit lookalike or brand impersonation patterns."],
            "model_status": "FROZEN"
        }


lookalike_service = LookalikeService()
