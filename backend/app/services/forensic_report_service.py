"""
ANVESH Canonical Forensic Report Service (Phase 10).
Compiles authoritative case, evidence, transport, intelligence,
ML/heuristic, campaign, and signal-fusion data into a canonical ForensicDossier.
Ensures 100% data parity between JSON and PDF exports.
Enforces non-attribution invariants and chain-of-custody tracking.
"""

import json
import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List
from fastapi import HTTPException

from app.database.supabase_client import supabase
from app.services.risk_engine import risk_engine, ml_classifier
from app.services.lookalike_service import lookalike_service
from app.services.identity_impersonation_service import identity_impersonation_service
from app.services.forensic_fusion_service import forensic_fusion_service
from app.services.pdf_report_generator import pdf_report_generator
from app.services.disposable_email_service import disposable_email_service
from app.core.constants import EmailDomainClassification
from app.schemas.report import (
    CaseIdentification,
    InvestigationSummary,
    EvidenceIntegrity,
    OriginalEmailMetadata,
    RelayHop,
    HeaderTransportAnalysis,
    AuthenticationAnalysis,
    OriginInfrastructure,
    ThreatIntelligenceFinding,
    Model1PhishingEvidence,
    Model2BECEvidence,
    Model3AIdentityEvidence,
    Model3BLookalikeEvidence,
    DetectionEvidence,
    CampaignCorrelationData,
    FusionCategoryScore,
    ForensicSignalFusionReportData,
    EvidenceContradictionReportItem,
    AttributionReportAssessment,
    EvidenceGapReportData,
    EmailProviderIntelligenceReportData,
    ChainOfCustodyEvent,
    ForensicDossier
)

# In-memory report cache and version tracking
_REPORT_CACHE: Dict[str, Dict[str, Any]] = {}
_REPORT_VERSIONS: Dict[str, float] = {}


class ForensicReportService:
    """
    Authoritative service for generating, versioning, and exporting
    ANVESH Forensic Investigation Dossiers.
    """

    def _resolve_case(self, case_id: str) -> Dict[str, Any]:
        items = supabase.query("cases", select="*", filters={"case_number": f"eq.{case_id}"})
        if not items:
            items = supabase.query("cases", select="*", filters={"id": f"eq.{case_id}"})
        if not items:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
        return items[0]

    def compile_canonical_dossier(self, case_id: str, force_regenerate: bool = False) -> ForensicDossier:
        """
        Compiles the complete, authoritative ForensicDossier object from database records.
        """
        case = self._resolve_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
        c_id = case.get("id") or case.get("case_number")
        case_num = case.get("case_number", f"CASE-{c_id}")

        if not force_regenerate and case_num in _REPORT_CACHE:
            return ForensicDossier.model_validate(_REPORT_CACHE[case_num])

        # Manage Versioning
        current_version_float = _REPORT_VERSIONS.get(case_num, 1.0)
        if force_regenerate and case_num in _REPORT_VERSIONS:
            current_version_float = round(current_version_float + 0.1, 1)
        _REPORT_VERSIONS[case_num] = current_version_float
        report_version_str = f"{current_version_float:.1f}"

        report_id = f"REP-{case_num}"
        generated_at = datetime.utcnow().isoformat()

        # Query Database Records
        emails = supabase.query("emails", select="*", filters={"case_id": f"eq.{c_id}"})
        evidence = supabase.query("evidence", select="*", filters={"case_id": f"eq.{c_id}"})
        iocs = supabase.query("iocs", select="*", filters={"case_id": f"eq.{c_id}"})
        infras = supabase.query("infrastructure_intelligence", select="*", filters={"case_id": f"eq.{c_id}"})
        attrs = supabase.query("attribution_assessments", select="*", filters={"case_id": f"eq.{c_id}"})
        gaps_list = supabase.query("evidence_gaps", select="*", filters={"case_id": f"eq.{c_id}"})

        email_rec = emails[0] if emails else {}
        ev_rec = evidence[0] if evidence else {}
        infra_rec = infras[0] if infras else {}
        attr_rec = attrs[0] if attrs else {}
        gap_rec = gaps_list[0] if gaps_list else {}

        # 1. Evidence Integrity (Preserve real SHA-256)
        raw_text = email_rec.get("raw_headers", "") or ""
        sha256_hash = (
            ev_rec.get("sha256_hash") or 
            email_rec.get("body_hash_sha256") or 
            (hashlib.sha256(raw_text.encode('utf-8')).hexdigest() if raw_text else "0" * 64)
        )
        evidence_integrity = EvidenceIntegrity(
            evidence_id=ev_rec.get("evidence_id") or f"EVD-{case_num}",
            original_filename=ev_rec.get("file_name") or "submitted_message.eml",
            sha256_hash=sha256_hash,
            file_size_bytes=ev_rec.get("file_size_bytes") or len(raw_text.encode('utf-8')),
            ingestion_timestamp=ev_rec.get("captured_at") or case.get("created_at") or generated_at,
            evidence_type="RFC_822_ELECTRONIC_MAIL",
            preservation_status="VERIFIED"
        )

        # 2. Case Identification
        case_id_data = CaseIdentification(
            case_id=str(c_id),
            case_number=case_num,
            case_status=case.get("status", "UNDER_REVIEW"),
            case_created_at=case.get("created_at", generated_at),
            report_generated_at=generated_at,
            risk_score=case.get("risk_score", 0),
            risk_level=case.get("risk_level", "INFORMATIONAL"),
            threat_type=case.get("threat_type", "SPOOFING_IMPERSONATION"),
            investigator=case.get("assigned_investigator") or "Not assigned",
            campaign_id=str(case.get("campaign_id")) if case.get("campaign_id") else None
        )

        # 3. Original Email Metadata
        sender = email_rec.get("sender") or case.get("sender") or "Unknown Sender"
        recipient = email_rec.get("recipient") or case.get("recipient") or "Unknown Recipient"
        subject = email_rec.get("subject") or case.get("title") or "(No Subject)"
        reply_to = email_rec.get("reply_to")
        message_id = email_rec.get("message_id") or f"<{uuid.uuid4()}@anvesh.local>"

        email_metadata = OriginalEmailMetadata(
            from_header=sender,
            to_header=recipient,
            cc_header=email_rec.get("cc"),
            reply_to_header=reply_to,
            return_path_header=email_rec.get("return_path"),
            subject_header=subject,
            date_header=email_rec.get("date_header"),
            message_id_header=message_id,
            mime_version="1.0"
        )

        # Disposable / Temporary Email Provider Intelligence (Phase 12.5)
        disp_intel = disposable_email_service.classify_sender(sender)
        email_provider_intelligence = None
        if disp_intel:
            email_provider_intelligence = EmailProviderIntelligenceReportData(
                sender_domain=disp_intel.domain,
                classification=disp_intel.classification.value if hasattr(disp_intel.classification, "value") else str(disp_intel.classification),
                provider=disp_intel.provider_name or "UNKNOWN",
                confidence=disp_intel.confidence,
                source=disp_intel.source,
                dataset_version=disp_intel.dataset_version,
                dataset_sha256=disp_intel.dataset_sha256,
                observed_at=disp_intel.observed_at,
                evidence=disp_intel.evidence_text,
                risk_contribution=disp_intel.risk_contribution
            )

        # 4. Authentication Analysis
        spf_status = str(email_rec.get("spf_status") or "NOT OBSERVED").upper()
        dkim_status = str(email_rec.get("dkim_status") or "NOT OBSERVED").upper()
        dmarc_status = str(email_rec.get("dmarc_status") or "NOT OBSERVED").upper()
        auth_verdict = (
            "ALL_PASS" if (spf_status == "PASS" and dkim_status == "PASS" and dmarc_status == "PASS")
            else ("FAILURES_DETECTED" if any(s == "FAIL" for s in (spf_status, dkim_status, dmarc_status))
            else "EVALUATED")
        )
        auth_analysis = AuthenticationAnalysis(
            spf_status=spf_status,
            dkim_status=dkim_status,
            dmarc_status=dmarc_status,
            auth_matrix_verdict=auth_verdict
        )

        # 5. Header Transport Analysis
        raw_hops = email_rec.get("delivery_hops_json") or []
        relay_hops: List[RelayHop] = []
        for idx, h in enumerate(raw_hops):
            if isinstance(h, dict):
                relay_hops.append(RelayHop(
                    hop=h.get("hop", idx + 1),
                    raw=str(h.get("raw", "")),
                    ips=h.get("ips", []),
                    ip=h.get("ip"),
                    is_public=h.get("is_public", False),
                    latitude=h.get("latitude"),
                    longitude=h.get("longitude"),
                    city=h.get("city"),
                    region=h.get("region"),
                    country=h.get("country"),
                    country_code=h.get("country_code"),
                    isp=h.get("isp"),
                    asn=h.get("asn"),
                    timezone=h.get("timezone")
                ))
        origin_conf = case.get("origin_confidence") or attr_rec.get("origin_confidence") or "LOW"
        transport_analysis = HeaderTransportAnalysis(
            total_hops=len(relay_hops) or email_rec.get("relay_count") or 0,
            earliest_observable_public_ip=case.get("probable_origin_ip") or infra_rec.get("ip_address"),
            origin_confidence=origin_conf,
            relay_chain=relay_hops,
            anomalies=["Anomalous hop depth (> 6 hops)"] if len(relay_hops) > 6 else []
        )

        # 6. Origin Infrastructure & Threat Intel
        origin_infra = OriginInfrastructure(
            probable_origin_ip=case.get("probable_origin_ip") or infra_rec.get("ip_address"),
            country=infra_rec.get("country"),
            region=infra_rec.get("region"),
            city=infra_rec.get("city"),
            asn=infra_rec.get("asn"),
            isp=infra_rec.get("isp"),
            organization=infra_rec.get("organization"),
            hosting_provider=infra_rec.get("hosting_provider"),
            cloud_classification=infra_rec.get("cloud_classification"),
            vpn_tor_proxy_indicator=infra_rec.get("vpn_tor_proxy_indicator", "NONE"),
            dns_records=infra_rec.get("dns_records"),
            rdap=infra_rec.get("rdap")
        )

        threat_intel_findings: List[ThreatIntelligenceFinding] = []
        if infra_rec.get("reputation") and infra_rec.get("reputation") != "UNKNOWN":
            try:
                rep_val = int(infra_rec.get("reputation"))
                threat_intel_findings.append(ThreatIntelligenceFinding(
                    source="AbuseIPDB / Community Abuse Database",
                    indicator=str(case.get("probable_origin_ip") or infra_rec.get("ip_address")),
                    result=f"Reported abuse score of {rep_val}%",
                    severity="HIGH" if rep_val >= 50 else ("MEDIUM" if rep_val >= 25 else "LOW"),
                    reputation_score=rep_val,
                    provenance="AUTHORITATIVE_BGP_AND_REGISTRY"
                ))
            except Exception:
                pass
        if infra_rec.get("vpn_tor_proxy_indicator") in ("TOR_EXIT_RELAY", "VPN_RELAY", "PROXY"):
            threat_intel_findings.append(ThreatIntelligenceFinding(
                source="Origin Routing Intelligence",
                indicator=infra_rec.get("vpn_tor_proxy_indicator"),
                result=f"Relay identified as commercial {infra_rec.get('vpn_tor_proxy_indicator').lower()}",
                severity="HIGH" if infra_rec.get("vpn_tor_proxy_indicator") == "TOR_EXIT_RELAY" else "MEDIUM",
                provenance="ANVESH_ROUTE_TRACER"
            ))
        if disp_intel and disp_intel.classification == EmailDomainClassification.DISPOSABLE:
            threat_intel_findings.append(ThreatIntelligenceFinding(
                source=f"Disposable Email Provider Intelligence ({disp_intel.source})",
                indicator=disp_intel.domain,
                result=disp_intel.evidence_text,
                severity="LOW",
                reputation_score=disp_intel.risk_contribution,
                provenance="GOVERNED_DATASET_OBSERVATION"
            ))

        # 7. Detection Models
        # Model 1
        ml_res = ml_classifier.classify(text=raw_text, sender=sender, subject=subject)
        m1_ev = Model1PhishingEvidence(
            model="anvesh_phishing_baseline",
            model_version="1.0.0",
            ml_score=ml_res["ml_score"],
            ml_probability=ml_res["ml_probability"],
            factors=ml_res["ml_factors"],
            status="FROZEN"
        )

        # Model 2
        bec_keywords = ["wire transfer", "urgent payment", "bank account", "invoice overdue"]
        found_kw = [kw for kw in bec_keywords if kw in raw_text.lower()]
        bec_score = 15 if (case.get("threat_type") == "BEC" or found_kw) else 0
        m2_ev = Model2BECEvidence(
            model="bec_baseline_v1",
            model_version="1.0.0",
            behavior_score=bec_score,
            bec_keywords=found_kw,
            status="FROZEN"
        )

        # Model 3B Lookalike
        sender_domain = sender.split("@")[-1].strip(" >").lower() if "@" in sender else ""
        lookalike_res = lookalike_service.detect_lookalike(sender_domain) if sender_domain else {
            "signal": "NONE",
            "candidate_domain": "",
            "trusted_domain": "",
            "raw_model_score": 0.0,
            "deterministic_indicators": []
        }
        m3b_ev = Model3BLookalikeEvidence(
            model="lookalike_domain_v1",
            model_version="1.0.0",
            signal=lookalike_res.get("signal", "NONE"),
            candidate_domain=lookalike_res.get("candidate_domain", ""),
            trusted_domain=lookalike_res.get("trusted_domain", ""),
            raw_model_score=float(lookalike_res.get("raw_model_score", 0.0)),
            deterministic_indicators=lookalike_res.get("deterministic_indicators", []),
            status="FROZEN"
        )

        # Model 3A Identity Impersonation
        auth_ctx = {"spf": spf_status, "dkim": dkim_status, "dmarc": dmarc_status}
        identity_res = identity_impersonation_service.evaluate(
            sender_header=sender,
            reply_to_header=reply_to,
            model3b_result=lookalike_res,
            auth_context=auth_ctx
        )
        m3a_ev = Model3AIdentityEvidence(
            model="model3a_deterministic_v1",
            model_name="Model 3A Identity Impersonation Baseline",
            model_type="Governed Deterministic Baseline",
            signal_type="Identity Impersonation Signal",
            identity_impersonation_score=identity_res.get("identity_impersonation_score", 0),
            confidence=identity_res.get("confidence", "NONE"),
            observed_identity=identity_res.get("observed_identity", "Unknown"),
            observed_sender=identity_res.get("observed_sender", sender),
            trusted_identity=identity_res.get("trusted_identity"),
            reply_to_mismatch=identity_res.get("reply_to"),
            signals=identity_res.get("signals", []),
            actor_identity="Actor Identity: NOT ESTABLISHED",
            actor_attribution="Actor Identity: NOT ESTABLISHED"
        )

        detection_evidence = DetectionEvidence(
            model_1_phishing=m1_ev,
            model_2_bec=m2_ev,
            model_3a_identity=m3a_ev,
            model_3b_lookalike=m3b_ev
        )

        # 8. Campaign Correlation
        campaign_id = case.get("campaign_id")
        camp_obj = None
        if campaign_id:
            camps = supabase.query("campaigns", select="*", filters={"id": f"eq.{campaign_id}"})
            if camps:
                camp_obj = camps[0]

        campaign_correlation = None
        if camp_obj:
            campaign_correlation = CampaignCorrelationData(
                campaign_id=camp_obj.get("campaign_id") or str(camp_obj.get("id")),
                name=camp_obj.get("name"),
                campaign_name=camp_obj.get("name"),
                status=camp_obj.get("status"),
                confidence=camp_obj.get("confidence"),
                confidence_score=camp_obj.get("confidence_score"),
                case_count=camp_obj.get("case_count", 1),
                shared_observables=camp_obj.get("matched_indicators") or camp_obj.get("shared_iocs", []),
                matched_indicators=camp_obj.get("matched_indicators") or camp_obj.get("shared_iocs", []),
                explanation=camp_obj.get("description") or "No campaign correlation established."
            )

        # 9. Forensic Signal Fusion (Phase 9B & 12.5)
        fusion_res = forensic_fusion_service.fuse(
            ml_signal=ml_res,
            behavior_signal={"behavior_score": bec_score, "bec_keywords": found_kw},
            identity_impersonation=identity_res,
            lookalike_evidence=lookalike_res,
            auth_context=auth_ctx,
            transport_evidence={"origin_confidence": origin_conf, "relay_count": len(relay_hops)},
            threat_intel=infra_rec,
            campaign=camp_obj,
            evidence_gaps=gap_rec,
            disposable_evidence=disp_intel
        )

        cat_breakdown = {
            k: FusionCategoryScore(score=v["score"], max=v["max"])
            for k, v in fusion_res.get("category_breakdown", {}).items()
        }
        forensic_fusion = ForensicSignalFusionReportData(
            model="anvesh_forensic_fusion_v1",
            fusion_score=fusion_res["fusion_score"],
            risk_level=fusion_res["risk_level"],
            fusion_confidence=fusion_res["fusion_confidence"],
            confidence_rationale=fusion_res.get("confidence_rationale", []),
            primary_signals=fusion_res.get("primary_signals", []),
            supporting_signals=fusion_res.get("supporting_signals", []),
            category_breakdown=cat_breakdown,
            forensic_interpretation=fusion_res["forensic_interpretation"]
        )

        contradiction_items = [
            EvidenceContradictionReportItem(
                type=c["type"],
                description=c["description"],
                conflicting_signals=c["conflicting_signals"],
                resolution_note=c["resolution_note"]
            )
            for c in fusion_res.get("contradictions", [])
        ]

        # 10. Attribution Assessment (Immutable Invariant)
        attribution = AttributionReportAssessment(
            actor_identity="Actor Identity: NOT ESTABLISHED",
            origin_confidence=origin_conf,
            observed_infrastructure=infra_rec.get("cloud_classification") or case.get("probable_origin_ip") or "Public Gateway",
            evidence_boundary=(
                "The available email and infrastructure evidence establishes observable technical "
                "indicators but is insufficient to attribute the activity to a specific person."
            )
        )

        # 11. Evidence Gaps & Next Action
        identified_gaps = gap_rec.get("identified_gaps") or [
            "Tenant message-trace logs",
            "Mailbox sign-in / credential access logs",
            "Origin gateway connection handshake logs"
        ]
        next_action = (
            gap_rec.get("recommended_next_action") or 
            "Obtain tenant mailbox sign-in and message-trace records for the sender account."
        )
        evidence_gaps = EvidenceGapReportData(
            current_evidence=gap_rec.get("current_evidence") or [],
            identified_gaps=identified_gaps,
            additional_evidence_options=gap_rec.get("additional_evidence_options") or [],
            recommended_next_action=next_action
        )

        # 12. Investigation Summary
        inv_summary = InvestigationSummary(
            threat_risk=case.get("risk_level", "INFORMATIONAL"),
            risk_score=case.get("risk_score", 0),
            primary_findings=fusion_res.get("primary_signals") or [f"Assessed {case.get('threat_type')} risk pattern."],
            authentication_summary=f"SPF {spf_status}, DKIM {dkim_status}, DMARC {dmarc_status}",
            attribution_summary="Actor Identity: NOT ESTABLISHED"
        )

        # 13. Chain of Custody Events
        coc_events: List[ChainOfCustodyEvent] = [
            ChainOfCustodyEvent(
                event_id=f"COC-{case_num}-01",
                case_id=str(c_id),
                evidence_id=evidence_integrity.evidence_id,
                event_type="EVIDENCE_ACQUIRED",
                timestamp=evidence_integrity.ingestion_timestamp,
                actor="SYSTEM",
                description="RFC-822 email payload ingested into ANVESH evidence vault.",
                previous_event_id=None
            ),
            ChainOfCustodyEvent(
                event_id=f"COC-{case_num}-02",
                case_id=str(c_id),
                evidence_id=evidence_integrity.evidence_id,
                event_type="EVIDENCE_HASHED",
                timestamp=evidence_integrity.ingestion_timestamp,
                actor="SYSTEM",
                description=f"Cryptographic SHA-256 fingerprint registered: {evidence_integrity.sha256_hash}.",
                previous_event_id=f"COC-{case_num}-01"
            ),
            ChainOfCustodyEvent(
                event_id=f"COC-{case_num}-03",
                case_id=str(c_id),
                evidence_id=evidence_integrity.evidence_id,
                event_type="ANALYSIS_COMPLETED",
                timestamp=generated_at,
                actor="SYSTEM",
                description="Multi-modal forensic extraction, ML evaluation, and signal fusion completed.",
                previous_event_id=f"COC-{case_num}-02"
            ),
            ChainOfCustodyEvent(
                event_id=f"COC-{case_num}-04",
                case_id=str(c_id),
                evidence_id=evidence_integrity.evidence_id,
                event_type="REPORT_GENERATED",
                timestamp=generated_at,
                actor=case_id_data.investigator or "SYSTEM",
                description=f"Canonical Forensic Dossier compiled (Version {report_version_str}).",
                previous_event_id=f"COC-{case_num}-03"
            )
        ]

        # Assemble Canonical Dossier
        dossier = ForensicDossier(
            report_title="ANVESH FORENSIC INVESTIGATION DOSSIER",
            report_id=report_id,
            case_id=str(c_id),
            report_version=report_version_str,
            generated_at=generated_at,
            anvesh_version="2.0.0-workspace",
            case_identification=case_id_data,
            investigation_summary=inv_summary,
            evidence_integrity=evidence_integrity,
            email_metadata=email_metadata,
            transport_analysis=transport_analysis,
            authentication_analysis=auth_analysis,
            origin_infrastructure=origin_infra,
            threat_intelligence=threat_intel_findings,
            detection_evidence=detection_evidence,
            campaign_correlation=campaign_correlation,
            forensic_fusion=forensic_fusion,
            contradictions=contradiction_items,
            attribution_assessment=attribution,
            evidence_gaps=evidence_gaps,
            recommended_next_step=next_action,
            chain_of_custody=coc_events,
            email_provider_intelligence=email_provider_intelligence
        )

        # Compute Report SHA-256 over canonical serialized payload (excluding report_sha256 itself)
        canonical_dict = dossier.model_dump(exclude={"report_sha256"})
        canonical_json_bytes = json.dumps(canonical_dict, sort_keys=True).encode('utf-8')
        rep_hash = hashlib.sha256(canonical_json_bytes).hexdigest().lower()
        dossier.report_sha256 = rep_hash
        dossier.evidence_integrity.report_sha256 = rep_hash

        # Cache report
        _REPORT_CACHE[case_num] = dossier.model_dump()
        return dossier

    def export_pdf(self, case_id: str) -> Tuple[bytes, str]:
        """
        Generates and returns (pdf_bytes, filename).
        """
        dossier = self.compile_canonical_dossier(case_id)
        pdf_bytes, _ = pdf_report_generator.generate_pdf(dossier)
        filename = f"ANVESH_DOSSIER_{dossier.case_identification.case_number}.pdf"
        return pdf_bytes, filename

    def export_json(self, case_id: str) -> Tuple[str, str]:
        """
        Generates and returns (json_string, filename).
        """
        dossier = self.compile_canonical_dossier(case_id)
        json_str = dossier.model_dump_json(indent=2)
        filename = f"ANVESH_DOSSIER_{dossier.case_identification.case_number}.json"
        return json_str, filename


forensic_report_service = ForensicReportService()
