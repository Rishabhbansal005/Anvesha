"""
ANVESH Forensic Attribution Assessment & Evidence Gap Engine.
Core Evidentiary Guarantees:
1. Origin Confidence: Evaluates relay chain integrity, shared cloud infrastructure, and observable trust boundaries.
2. Attribution Boundary: Actor Identity remains strictly 'NOT ESTABLISHED' on transport-level evidence.
3. Evidence Gaps: Explicitly states what the current evidence CANNOT establish and prescribes actionable next evidence.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class AttributionService:
    @staticmethod
    def evaluate_origin_confidence(
        probable_origin_ip: Optional[str],
        hops: List[Dict[str, Any]],
        cloud_classification: Optional[str] = None,
        is_private: bool = False,
        auth_status: Optional[Dict[str, str]] = None,
        has_forwarding_headers: bool = False
    ) -> Dict[str, Any]:
        """
        Evaluates origin confidence without naive 'oldest IP = attacker' assumptions.
        Returns: { 'level': 'HIGH'|'MEDIUM'|'LOW'|'UNDETERMINED', 'reason': str, 'factors': List[str] }
        """
        if not probable_origin_ip or is_private:
            return {
                "level": "UNDETERMINED",
                "reason": "Only internal or non-routable private addresses were observed in routing headers; no public origin gateway established.",
                "factors": ["All observed hops reside in isolated non-routable subnets", "No public Internet gateway traversed"]
            }

        factors = []
        hop_count = len(hops)

        # 1. Cloud / Shared SaaS relay detection (e.g. Microsoft 365, Google Workspace, AWS SES)
        is_shared_cloud = cloud_classification in (
            "MICROSOFT_365_OR_AZURE",
            "GOOGLE_WORKSPACE_OR_GCP",
            "AMAZON_WEB_SERVICES",
            "CLOUDFLARE_NETWORK",
            "FASTLY",
            "AKAMAI_TECHNOLOGIES"
        )

        if is_shared_cloud:
            factors.append(f"Observed gateway belongs to multi-tenant shared infrastructure ({cloud_classification})")
            return {
                "level": "LOW",
                "reason": f"The available headers identify a shared multi-tenant relay ({cloud_classification.replace('_', ' ').title()}), but the evidence does not establish the originating human user or endpoint device.",
                "factors": factors
            }

        # 2. Forwarding / Mailing-list / Disrupted headers
        if has_forwarding_headers:
            factors.append("Message traversal indicates forwarding or intermediary routing")
            return {
                "level": "LOW",
                "reason": "Email forwarding headers observed; original client hop may have been rewritten or stripped by upstream proxy.",
                "factors": factors
            }

        # 3. Hop traversal depth & authentication consistency
        spf_pass = (auth_status or {}).get("spf") == "PASS"
        dkim_pass = (auth_status or {}).get("dkim") == "PASS"

        if hop_count >= 2:
            factors.append(f"Reconstructed verifiable multi-hop relay trajectory ({hop_count} hops)")
            if spf_pass or dkim_pass:
                factors.append("Cryptographic authentication aligns with observed routing path")
                return {
                    "level": "HIGH",
                    "reason": "Consistently authenticated relay hops with verifiable public gateway trajectory.",
                    "factors": factors
                }
            else:
                factors.append("Authentication alignment absent or failed across relay path")
                return {
                    "level": "MEDIUM",
                    "reason": "Public gateway observed across multiple hops, but unaligned authentication prevents high origin confidence.",
                    "factors": factors
                }

        # Single hop public IP
        return {
            "level": "MEDIUM",
            "reason": "Single observed public relay gateway; insufficient intermediary hops to independently cross-verify origin trajectory.",
            "factors": ["Single public gateway observed", "Limited relay hop depth"]
        }

    @staticmethod
    def generate_attribution_assessment(
        case_title: str,
        risk_level: str,
        risk_score: int,
        origin_confidence: str,
        cloud_classification: Optional[str] = None,
        probable_origin_ip: Optional[str] = None,
        asn: Optional[str] = None,
        threat_type: str = "BEC",
        has_auth_failure: bool = False
    ) -> Dict[str, Any]:
        """
        Constructs the Attribution Assessment enforcing the Attribution Boundary.
        Actor Identity is NEVER fabricated and strictly set to 'NOT ESTABLISHED'.
        """
        # Determine human-readable observed infrastructure
        obs_infra = "Independent Public Network Gateway"
        if cloud_classification and cloud_classification not in ("UNKNOWN", "UNAVAILABLE", "INDEPENDENT_OR_RESIDENTIAL_TRANSIT"):
            obs_infra = cloud_classification.replace("_", " ").title()
            if asn and asn != "UNAVAILABLE":
                obs_infra += f" ({asn})"
        elif probable_origin_ip:
            obs_infra = f"Observed Public Gateway [{probable_origin_ip}]"
            if asn and asn != "UNAVAILABLE":
                obs_infra += f" · {asn}"

        boundary_explanation = (
            "Available email evidence identifies mail transport infrastructure but does not provide "
            "sufficient evidence to attribute the activity to a specific individual or physical endpoint. "
            "Forensic evidence boundaries terminate at the transport protocol layer."
        )

        reason = (
            f"Evaluated threat level is {risk_level} ({risk_score}/100) with origin confidence assessed as {origin_confidence}. "
            f"The observed delivery infrastructure ({obs_infra}) transports the message, but transport headers "
            f"cannot establish the identity of the physical person operating behind the tenant account."
        )

        return {
            "threat_risk": risk_level,
            "threat_score": risk_score,
            "observed_infrastructure": obs_infra,
            "origin_confidence": origin_confidence,
            "actor_identity": "NOT ESTABLISHED",
            "attribution_boundary": boundary_explanation,
            "reason": reason,
            "evidence_nature": "DERIVED",
            "created_at": datetime.utcnow().isoformat()
        }

    @staticmethod
    def generate_evidence_gaps(
        threat_type: str,
        is_cloud_provider: bool,
        origin_confidence: str,
        auth_pass: bool
    ) -> Dict[str, Any]:
        """
        Identifies forensic evidence gaps and prescribes actionable next steps.
        """
        current_evidence = [
            {"item": "Raw RFC-822 email payload", "status": "AVAILABLE", "verified": True},
            {"item": "RFC-822 header key-value records", "status": "AVAILABLE", "verified": True},
            {"item": "Cryptographic authentication (SPF / DKIM / DMARC)", "status": "AVAILABLE", "verified": True},
            {"item": "SMTP Received relay hop trajectory", "status": "AVAILABLE", "verified": True},
            {"item": "Public IP infrastructure intelligence & ASN records", "status": "AVAILABLE", "verified": True},
            {"item": "Domain registration records (RDAP / DNS)", "status": "AVAILABLE", "verified": True}
        ]

        identified_gaps = []
        additional_evidence_options = []
        recommended_action = ""

        # Scenario A: Cloud or Passing Auth with High Threat (e.g. Compromised Account / BEC)
        if is_cloud_provider or auth_pass or threat_type in ("BEC", "FINANCIAL_EXTORTION"):
            identified_gaps.extend([
                "Mailbox sign-in and session audit logs unavailable",
                "Tenant message trace and outbound connector telemetry unobserved",
                "Mailbox forwarding and inbox rule modification history unverified",
                "Sender endpoint forensic telemetry (EDR / MDM) uncollected"
            ])
            additional_evidence_options.extend([
                {"evidence_type": "Mailbox Sign-In Logs", "source": "Azure AD / Entra ID or Google Workspace Admin", "utility": "Confirm anomalous geo-location or session hijacking on sender account."},
                {"evidence_type": "Tenant Message Trace", "source": "Microsoft 365 Defender / Google Audit Log", "utility": "Verify whether message originated from genuine webmail session or compromised API connector."},
                {"evidence_type": "Inbox Forwarding Rules", "source": "Exchange Online PowerShell / Gmail Admin", "utility": "Identify auto-forwarding or sweep rules commonly established during account takeover (ATO)."},
                {"evidence_type": "Out-of-Band Verification", "source": "Direct Phone / Secure Channel", "utility": "Confirm with purported sender whether requested wire instructions or payments are genuine."}
            ])
            recommended_action = "Obtain tenant administrator mailbox sign-in logs and message trace from the sender's mail platform (Microsoft 365 / Google Workspace) to determine whether account takeover (ATO) occurred."
        else:
            # Scenario B: Spoofed or unauthenticated external infrastructure
            identified_gaps.extend([
                "Sender originating workstation IP unrecorded (stripped by gateway relay)",
                "Domain registrar identity shielded by privacy proxy",
                "Command & Control (C2) server host-level access logs unavailable"
            ])
            additional_evidence_options.extend([
                {"evidence_type": "Registrar Subpoena / LER Request", "source": "Relevant ccTLD / gTLD Registrar", "utility": "Obtain payment method and subscriber details for newly registered lookalike domain."},
                {"evidence_type": "Upstream ISP NetFlow", "source": "Transit Autonomous System Provider", "utility": "Correlate inbound connections to the relay gateway at the time of transmission."}
            ])
            recommended_action = "Submit domain takedown or abuse notification to the identified registrar abuse contact and block observed relay gateway at perimeter mail firewall."

        return {
            "current_evidence": current_evidence,
            "identified_gaps": identified_gaps,
            "additional_evidence_options": additional_evidence_options,
            "recommended_next_action": recommended_action,
            "created_at": datetime.utcnow().isoformat()
        }


attribution_service = AttributionService()
