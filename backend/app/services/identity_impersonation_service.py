"""
ANVESH Backend Identity Impersonation Service.
Integrates Model 3A (identity_impersonation_predictor) into ANVESH email investigation pipelines.
Enforces forensic attribution boundaries:
- Evidence / correlation signal only
- NEVER asserts or establishes actor identity
- MANDATORY LANGUAGE: "Actor Identity: NOT ESTABLISHED"
"""

import logging
from typing import Dict, Any, List, Optional
import sys
from pathlib import Path

# Ensure repository root is on sys.path
_repo_root = str(Path(__file__).resolve().parent.parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from ml.inference.identity_impersonation_predictor import (
    get_identity_impersonation_predictor,
    IdentityImpersonationPredictor
)

logger = logging.getLogger(__name__)

# Governed Curated Registry Interface for Testing & Demonstrations
# CRITICAL GOVERNANCE NOTE: These identities are strictly DEMONSTRATION TEST FIXTURES.
TEST_IDENTITY_REGISTRY: List[Dict[str, Any]] = [
    {
        "identity_id": "TID-EXEC-001",
        "display_name": "Anita Sharma",
        "email": "anita.sharma@company.com",
        "domain": "company.com",
        "identity_type": "EXECUTIVE",
        "verification_source": "TEST FIXTURE",
        "verified": True
    },
    {
        "identity_id": "TID-EXEC-002",
        "display_name": "John Smith",
        "email": "john.smith@company.com",
        "domain": "company.com",
        "identity_type": "EXECUTIVE",
        "verification_source": "TEST FIXTURE",
        "verified": True
    },
    {
        "identity_id": "TID-SUPP-001",
        "display_name": "ABC Supplies",
        "email": "billing@abc-supplies.com",
        "domain": "abc-supplies.com",
        "identity_type": "SUPPLIER",
        "verification_source": "TEST FIXTURE",
        "verified": True
    },
    {
        "identity_id": "TID-SUPP-002",
        "display_name": "Apex Cloud Logistics",
        "email": "remittance@apexlogistics.corp",
        "domain": "apexlogistics.corp",
        "identity_type": "SUPPLIER",
        "verification_source": "TEST FIXTURE",
        "verified": True
    }
]


class IdentityImpersonationService:
    def __init__(self):
        try:
            self.predictor = get_identity_impersonation_predictor()
            self.available = True
        except Exception as e:
            logger.error(f"IdentityImpersonationService initialization failed: {e}")
            self.predictor = None
            self.available = False

    def lookup_test_identity(self, display_name: str, sender_email: str = "") -> Optional[Dict[str, Any]]:
        """
        Scans test fixture registry to find if a display name or email corresponds to a known identity.
        Does not fabricate identities if none match.
        """
        if not display_name and not sender_email:
            return None

        clean_name = display_name.lower().strip()
        clean_email = sender_email.lower().strip()

        for ident in TEST_IDENTITY_REGISTRY:
            reg_name = ident["display_name"].lower()
            reg_email = ident["email"].lower()

            if clean_name and reg_name in clean_name:
                return ident
            if clean_email and clean_email == reg_email:
                return ident

        return None

    def evaluate(
        self,
        sender_header: str,
        reply_to_header: Optional[str] = None,
        trusted_identity: Optional[Dict[str, Any]] = None,
        model3b_result: Optional[Dict[str, Any]] = None,
        auth_context: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates email headers for identity & header impersonation evidence.
        """
        if not self.available or self.predictor is None:
            return {
                "model": "model3a_deterministic_v1",
                "identity_impersonation_detected": False,
                "identity_impersonation_score": 0,
                "confidence": "UNKNOWN",
                "observed_identity": sender_header,
                "observed_sender": sender_header,
                "observed_local_part": "",
                "observed_domain": "",
                "reply_to": reply_to_header,
                "trusted_identity": None,
                "signals": [],
                "score_breakdown": [],
                "authentication_context": auth_context or {},
                "attribution": {
                    "actor_identity": "NOT ESTABLISHED"
                },
                "disclaimer": "Model 3A predictor service is currently unavailable.",
                "model_status": "UNAVAILABLE"
            }

        # If trusted identity not explicitly supplied, check governed test fixture registry
        effective_trusted = trusted_identity
        if not effective_trusted:
            obs_display, obs_addr, _, _ = self.predictor.extract_address_components(sender_header)
            effective_trusted = self.lookup_test_identity(obs_display, obs_addr)

        return self.predictor.predict(
            sender_header=sender_header,
            reply_to_header=reply_to_header,
            trusted_identity=effective_trusted,
            model3b_result=model3b_result,
            auth_context=auth_context
        )


identity_impersonation_service = IdentityImpersonationService()
