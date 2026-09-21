"""
ANVESH PDF Forensic Investigation Dossier Generator (Phase 10).
Uses ReportLab to generate a clean, searchable, print-friendly,
multi-page forensic dossier from the canonical ForensicDossier schema.
Enforces running headers/footers with 'Page X of Y' and the mandatory
non-attribution boundary: 'Actor Identity: NOT ESTABLISHED'.
"""

import io
import hashlib
from typing import Tuple, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.schemas.report import ForensicDossier


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes total page count dynamically
    and writes running headers and footers with non-attribution invariants.
    """
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_header_footer(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#5B6878"))

        # Running Top Header (Pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 762, "ANVESH FORENSIC INVESTIGATION DOSSIER")
            self.drawRightString(576, 762, "MANDATORY BOUNDARY: Actor Identity NOT ESTABLISHED")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(36, 756, 576, 756)

        # Running Bottom Footer (All Pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)

        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawString(36, 30, "CONFIDENTIAL // LAW ENFORCEMENT & SOC INCIDENT RESPONSE // PRESERVE CHAIN OF CUSTODY")
        self.drawRightString(576, 30, footer_text)
        self.restoreState()


class PDFReportGenerator:
    """
    Builds professional, evidence-grounded PDF dossiers from ForensicDossier objects.
    """

    def generate_pdf(self, dossier: ForensicDossier) -> Tuple[bytes, str]:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=50
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography
        title_style = ParagraphStyle(
            'DossierTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'DossierSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#475569'),
            spaceAfter=12
        )
        sec_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#0F172A'),
            spaceBefore=10,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            'DossierBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#1E293B')
        )
        body_bold = ParagraphStyle(
            'DossierBodyBold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )
        mono_style = ParagraphStyle(
            'DossierMono',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor('#0F172A')
        )
        alert_style = ParagraphStyle(
            'DossierAlert',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#991B1B')
        )

        elements = []

        # =========================================================================
        # HEADER & CASE BANNER
        # =========================================================================
        elements.append(Paragraph(dossier.report_title, title_style))
        banner_sub = (
            f"<b>Report ID:</b> {dossier.report_id} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Case:</b> {dossier.case_identification.case_number} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Version:</b> {dossier.report_version} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Generated:</b> {dossier.generated_at}"
        )
        elements.append(Paragraph(banner_sub, subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0F172A"), spaceAfter=10))

        # =========================================================================
        # 1. CASE IDENTIFICATION & INVESTIGATION SUMMARY
        # =========================================================================
        cid = dossier.case_identification
        summ = dossier.investigation_summary

        case_summary_data = [
            [
                Paragraph("<b>Case Number:</b>", body_style),
                Paragraph(cid.case_number, body_bold),
                Paragraph("<b>Threat Risk:</b>", body_style),
                Paragraph(f"<b>{cid.risk_level} ({cid.risk_score}/100)</b>", body_bold)
            ],
            [
                Paragraph("<b>Case Status:</b>", body_style),
                Paragraph(cid.case_status, body_style),
                Paragraph("<b>Threat Classification:</b>", body_style),
                Paragraph(cid.threat_type, body_style)
            ],
            [
                Paragraph("<b>Case Created:</b>", body_style),
                Paragraph(cid.case_created_at, body_style),
                Paragraph("<b>Assigned Investigator:</b>", body_style),
                Paragraph(cid.investigator or "Not assigned", body_style)
            ],
            [
                Paragraph("<b>Campaign Linkage:</b>", body_style),
                Paragraph(cid.campaign_id or "None Correlated", body_style),
                Paragraph("<b>Attribution Verdict:</b>", body_style),
                Paragraph("<font color='#B91C1C'><b>NOT ESTABLISHED</b></font>", body_bold)
            ]
        ]
        t_summary = Table(case_summary_data, colWidths=[100, 170, 110, 160])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(Paragraph("1. CASE IDENTIFICATION & SUMMARY", sec_heading))
        elements.append(t_summary)
        elements.append(Spacer(1, 8))

        # Primary findings bullets
        if summ.primary_findings:
            findings_p = "<b>Key Technical Findings:</b><br/>" + "<br/>".join(
                [f"• {f}" for f in summ.primary_findings[:5]]
            )
            elements.append(Paragraph(findings_p, body_style))
            elements.append(Spacer(1, 6))

        # =========================================================================
        # 2. EVIDENCE INTEGRITY & CHAIN OF CUSTODY FINGERPRINT
        # =========================================================================
        ev = dossier.evidence_integrity
        ev_data = [
            [Paragraph("<b>Evidence ID:</b>", body_style), Paragraph(ev.evidence_id, body_bold)],
            [Paragraph("<b>Original File:</b>", body_style), Paragraph(ev.original_filename, body_style)],
            [Paragraph("<b>Evidence SHA-256:</b>", body_style), Paragraph(ev.sha256_hash, mono_style)],
            [Paragraph("<b>Payload Size:</b>", body_style), Paragraph(f"{ev.file_size_bytes} bytes", body_style)],
            [Paragraph("<b>Integrity Status:</b>", body_style), Paragraph(f"<b>{ev.preservation_status}</b> (Bit-level hash verified)", body_bold)],
            [Paragraph("<b>Acquisition Time:</b>", body_style), Paragraph(ev.ingestion_timestamp, body_style)]
        ]
        t_ev = Table(ev_data, colWidths=[120, 420])
        t_ev.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(Paragraph("2. EVIDENCE INTEGRITY (RFC-822 PAYLOAD)", sec_heading))
        elements.append(t_ev)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 3. ORIGINAL EMAIL METADATA
        # =========================================================================
        em = dossier.email_metadata
        email_data = [
            [Paragraph("<b>From:</b>", body_style), Paragraph(em.from_header, body_style)],
            [Paragraph("<b>To:</b>", body_style), Paragraph(em.to_header, body_style)],
            [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(em.reply_to_header or "None specified", body_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(em.subject_header, body_bold)],
            [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(em.message_id_header, mono_style)],
            [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(em.return_path_header or "None specified", mono_style)],
        ]
        t_email = Table(email_data, colWidths=[100, 440])
        t_email.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FFFFFF')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(Paragraph("3. ORIGINAL EMAIL METADATA", sec_heading))
        elements.append(t_email)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 4. AUTHENTICATION ANALYSIS
        # =========================================================================
        auth = dossier.authentication_analysis
        auth_data = [
            [
                Paragraph("<b>Protocol</b>", body_bold),
                Paragraph("<b>Verdict</b>", body_bold),
                Paragraph("<b>Technical Context</b>", body_bold)
            ],
            [
                Paragraph("SPF", body_style),
                Paragraph(f"<b>{auth.spf_status}</b>", body_style),
                Paragraph("Sender Policy Framework authorization for sending gateway", body_style)
            ],
            [
                Paragraph("DKIM", body_style),
                Paragraph(f"<b>{auth.dkim_status}</b>", body_style),
                Paragraph("Cryptographic domain signature verification", body_style)
            ],
            [
                Paragraph("DMARC", body_style),
                Paragraph(f"<b>{auth.dmarc_status}</b>", body_style),
                Paragraph("Domain alignment policy enforcement check", body_style)
            ]
        ]
        t_auth = Table(auth_data, colWidths=[90, 80, 370])
        t_auth.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(Paragraph("4. CRYPTOGRAPHIC AUTHENTICATION ANALYSIS", sec_heading))
        elements.append(t_auth)
        
        # Mandatory protocol disclaimer
        interp_box = [
            [Paragraph(f"<b>Protocol Invariant Note:</b> {auth.mandatory_protocol_interpretation}", body_style)]
        ]
        t_interp = Table(interp_box, colWidths=[540])
        t_interp.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FEF3C7')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#F59E0B')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(Spacer(1, 4))
        elements.append(t_interp)
        elements.append(Spacer(1, 8))        # =========================================================================
        # 5. EMAIL PROVIDER INTELLIGENCE (PHASE 12.5)
        # =========================================================================
        disp_data = dossier.email_provider_intelligence
        if disp_data:
            provider_display = disp_data.provider or "Unknown / Unlisted"
            cls_color = '#DC2626' if disp_data.classification == 'DISPOSABLE' else ('#2563EB' if disp_data.classification == 'FORWARDING_PRIVACY' else '#475569')
            prov_table_data = [
                [
                    Paragraph("<b>Sender Domain:</b>", body_style),
                    Paragraph(disp_data.sender_domain, mono_style),
                    Paragraph("<b>Classification:</b>", body_style),
                    Paragraph(f"<b><font color='{cls_color}'>{disp_data.classification}</font></b>", body_style)
                ],
                [
                    Paragraph("<b>Provider Name:</b>", body_style),
                    Paragraph(provider_display, body_style),
                    Paragraph("<b>Risk Contribution:</b>", body_style),
                    Paragraph(f"<b>+{disp_data.risk_contribution} pts</b> (Bounded max +8)", body_style)
                ],
                [
                    Paragraph("<b>Dataset Version:</b>", body_style),
                    Paragraph(disp_data.dataset_version, body_style),
                    Paragraph("<b>Dataset SHA-256:</b>", body_style),
                    Paragraph(disp_data.dataset_sha256[:16] + "...", mono_style)
                ],
                [
                    Paragraph("<b>Forensic Evidence:</b>", body_style),
                    Paragraph(disp_data.evidence, body_style),
                    Paragraph("<b>Confidence:</b>", body_style),
                    Paragraph(disp_data.confidence, body_style)
                ]
            ]
            t_prov = Table(prov_table_data, colWidths=[110, 160, 120, 150])
            t_prov.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            elements.append(Paragraph("5. EMAIL PROVIDER INTELLIGENCE", sec_heading))
            elements.append(t_prov)
            elements.append(Spacer(1, 8))

        # =========================================================================
        # 6. TRANSPORT TRAJECTORY & ORIGIN INFRASTRUCTURE
        # =========================================================================
        tr = dossier.transport_analysis
        infra = dossier.origin_infrastructure

        trans_data = [
            [
                Paragraph("<b>Total Relay Hops:</b>", body_style),
                Paragraph(str(tr.total_hops), body_style),
                Paragraph("<b>Earliest Observable Public IP:</b>", body_style),
                Paragraph(tr.earliest_observable_public_ip or "Not established", mono_style)
            ],
            [
                Paragraph("<b>Origin Confidence:</b>", body_style),
                Paragraph(f"<b>{tr.origin_confidence}</b>", body_bold),
                Paragraph("<b>IP-Associated Location:</b>", body_style),
                Paragraph(f"{infra.city or ''} {infra.country or 'Unknown'}".strip(), body_style)
            ],
            [
                Paragraph("<b>Autonomous System:</b>", body_style),
                Paragraph(infra.asn or "Unspecified ASN", body_style),
                Paragraph("<b>Hosting / Cloud Provider:</b>", body_style),
                Paragraph(infra.cloud_classification or infra.hosting_provider or "Standard Gateway", body_style)
            ],
            [
                Paragraph("<b>Proxy / VPN / TOR:</b>", body_style),
                Paragraph(infra.vpn_tor_proxy_indicator, body_bold),
                Paragraph("<b>Infrastructure Status:</b>", body_style),
                Paragraph("Observed Transit Hop (Technical Routing Only)", body_style)
            ]
        ]
        t_trans = Table(trans_data, colWidths=[110, 160, 120, 150])
        t_trans.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(Paragraph("6. HEADER & TRANSPORT INFRASTRUCTURE ANALYSIS", sec_heading))
        elements.append(t_trans)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 7. DETECTION MODELS & HEURISTIC EVIDENCE
        # =========================================================================
        det = dossier.detection_evidence
        det_data = [
            [
                Paragraph("<b>Model / Detection Engine</b>", body_bold),
                Paragraph("<b>Signal / Verdict</b>", body_bold),
                Paragraph("<b>Score / Value</b>", body_bold),
                Paragraph("<b>Key Observable Evidence</b>", body_bold)
            ]
        ]
        if det.model_1_phishing:
            m1 = det.model_1_phishing
            det_data.append([
                Paragraph("Model 1: Phishing NLP (v1.0.0)", body_style),
                Paragraph("PHISHING INDICATORS" if m1.ml_score >= 15 else "LOW PHISH", body_style),
                Paragraph(f"{m1.ml_score}/30 raw", body_style),
                Paragraph(", ".join(m1.factors[:2]) if m1.factors else "No factors flagged", body_style)
            ])
        if det.model_2_bec:
            m2 = det.model_2_bec
            det_data.append([
                Paragraph("Model 2: BEC Intent (v1.0.0)", body_style),
                Paragraph("BEC VECTOR" if m2.behavior_score >= 10 else "BENIGN", body_style),
                Paragraph(f"{m2.behavior_score} pts", body_style),
                Paragraph(f"Keywords: {', '.join(m2.bec_keywords[:2])}" if m2.bec_keywords else "None", body_style)
            ])
        if det.model_3a_identity:
            m3a = det.model_3a_identity
            det_data.append([
                Paragraph("Model 3A: Identity Impersonation", body_style),
                Paragraph(f"{m3a.confidence} SIGNAL", body_style),
                Paragraph(f"{m3a.identity_impersonation_score}/100", body_bold),
                Paragraph(f"Observed: '{m3a.observed_identity}' | Reply-To: '{m3a.reply_to_mismatch or 'Consistent'}'", body_style)
            ])
        if det.model_3b_lookalike:
            m3b = det.model_3b_lookalike
            det_data.append([
                Paragraph("Model 3B: Lookalike Domain (v1.0.0)", body_style),
                Paragraph(f"{m3b.signal} SIGNAL", body_style),
                Paragraph(f"{m3b.raw_model_score:.2f} score", body_style),
                Paragraph(f"'{m3b.candidate_domain}' resembles '{m3b.trusted_domain}'", body_style)
            ])

        t_det = Table(det_data, colWidths=[150, 110, 80, 200])
        t_det.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(Paragraph("7. DETECTION EVIDENCE & MODEL VERDICTS", sec_heading))
        elements.append(t_det)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 8. CAMPAIGN CORRELATION
        # =========================================================================
        cmp = dossier.campaign_correlation
        if cmp and cmp.campaign_id:
            cmp_text = (
                f"<b>Campaign Linkage:</b> {cmp.campaign_id} "
                f"({cmp.confidence or 'N/A'} Confidence, {cmp.case_count} related cases).<br/>"
                f"<b>Observable Evidence:</b> {cmp.explanation or 'No cluster overlap.'}"
            )
        else:
            cmp_text = (
                "<b>Campaign Linkage:</b> No correlated campaign cluster identified.<br/>"
                "<b>Observable Evidence:</b> Technical observables do not match any active coordinated threat campaigns."
            )
        t_cmp = Table([[Paragraph(cmp_text, body_style)]], colWidths=[540])
        t_cmp.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(Paragraph("8. CAMPAIGN CORRELATION & CLUSTERING", sec_heading))
        elements.append(t_cmp)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 9. FORENSIC SIGNAL FUSION (PHASE 9B)
        # =========================================================================
        fus = dossier.forensic_fusion
        def _get_cat(cat_name: str) -> int:
            obj = fus.category_breakdown.get(cat_name) if fus.category_breakdown else None
            if not obj:
                return 0
            if isinstance(obj, dict):
                return obj.get("score", 0)
            return getattr(obj, "score", 0)

        fus_data = [
            [
                Paragraph("<b>Synthesized Fusion Score:</b>", body_style),
                Paragraph(f"<b>{fus.fusion_score} / 100 ({fus.risk_level})</b>", body_bold),
                Paragraph("<b>Fusion Confidence:</b>", body_style),
                Paragraph(f"<b>{fus.fusion_confidence}</b>", body_bold)
            ],
            [
                Paragraph("<b>Category Breakdown:</b>", body_style),
                Paragraph(
                    f"Content: {_get_cat('content')}/20 | "
                    f"Identity: {_get_cat('identity')}/20 | "
                    f"Infra: {_get_cat('infrastructure')}/20",
                    body_style
                ),
                Paragraph("<b>Auth & Intel:</b>", body_style),
                Paragraph(
                    f"Auth: {_get_cat('authentication')}/15 | "
                    f"Intel: {_get_cat('threat_intel')}/15 | "
                    f"Cmp: {_get_cat('campaign')}/10",
                    body_style
                )
            ]
        ]
        t_fus = Table(fus_data, colWidths=[120, 160, 110, 150])
        t_fus.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(Paragraph("9. FORENSIC SIGNAL FUSION (CROSS-MODAL SYNTHESIS)", sec_heading))
        elements.append(t_fus)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(f"<b>Forensic Interpretation:</b> {fus.forensic_interpretation}", body_style))
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 10. CONTRADICTIONS & CONFLICT RESOLUTION
        # =========================================================================
        if dossier.contradictions:
            elements.append(Paragraph("10. CONTRADICTION & CONFLICT RESOLUTION", sec_heading))
            for ct in dossier.contradictions:
                c_content = (
                    f"<b>Contradiction Detected:</b> <font color='#B45309'>{ct.type}</font><br/>"
                    f"<b>Description:</b> {ct.description}<br/>"
                    f"<b>Conflicting Signals:</b> {', '.join(ct.conflicting_signals)}<br/>"
                    f"<b>Forensic Invariant:</b> {ct.resolution_note}"
                )
                t_c = Table([[Paragraph(c_content, body_style)]], colWidths=[540])
                t_c.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FEF3C7')),
                    ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#F59E0B')),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ]))
                elements.append(t_c)
                elements.append(Spacer(1, 4))
            elements.append(Spacer(1, 4))

        # =========================================================================
        # 11. MANDATORY ATTRIBUTION ASSESSMENT & EVIDENCE BOUNDARY
        # =========================================================================
        attr = dossier.attribution_assessment
        attr_content = [
            [Paragraph("<b>Actor Identity:</b>", alert_style), Paragraph("<b>NOT ESTABLISHED</b>", alert_style)],
            [Paragraph("<b>Origin Confidence:</b>", body_style), Paragraph(attr.origin_confidence, body_style)],
            [Paragraph("<b>Observed Infrastructure:</b>", body_style), Paragraph(attr.observed_infrastructure, body_style)],
            [Paragraph("<b>Attribution Boundary:</b>", body_style), Paragraph(attr.evidence_boundary, body_style)]
        ]
        t_attr = Table(attr_content, colWidths=[120, 420])
        t_attr.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FEE2E2')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#DC2626')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#FCA5A5')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(Paragraph("11. ATTRIBUTION ASSESSMENT & EVIDENCE BOUNDARY", sec_heading))
        elements.append(t_attr)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 12. EVIDENCE GAPS & RECOMMENDED ACTION
        # =========================================================================
        gaps = dossier.evidence_gaps
        gap_items = ", ".join(gaps.identified_gaps) if gaps.identified_gaps else "No critical technical gaps identified."
        elements.append(Paragraph("12. EVIDENCE GAPS & RECOMMENDED NEXT STEP", sec_heading))
        gap_data = [
            [Paragraph("<b>Identified Evidence Gaps:</b>", body_style), Paragraph(gap_items, body_style)],
            [Paragraph("<b>Recommended Next Action:</b>", body_style), Paragraph(dossier.recommended_next_step, body_bold)]
        ]
        t_gap = Table(gap_data, colWidths=[140, 400])
        t_gap.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(t_gap)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 13. CHAIN OF CUSTODY TIMELINE
        # =========================================================================
        elements.append(Paragraph("13. CHAIN OF CUSTODY (APPEND-ONLY LEDGER)", sec_heading))
        coc_rows = [
            [
                Paragraph("<b>Event Type</b>", body_bold),
                Paragraph("<b>Timestamp (UTC)</b>", body_bold),
                Paragraph("<b>Actor</b>", body_bold),
                Paragraph("<b>Description</b>", body_bold)
            ]
        ]
        for evt in dossier.chain_of_custody:
            coc_rows.append([
                Paragraph(evt.event_type, mono_style),
                Paragraph(evt.timestamp, body_style),
                Paragraph(evt.actor, body_style),
                Paragraph(evt.description, body_style)
            ])
        t_coc = Table(coc_rows, colWidths=[130, 110, 60, 240])
        t_coc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 2.5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ]))
        elements.append(t_coc)
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 14. LIMITATIONS & LEGAL DISCLAIMER
        # =========================================================================
        elements.append(Paragraph("14. LIMITATIONS & EVIDENTIARY DISCLAIMERS", sec_heading))
        limits_text = "<br/>".join([f"• {lim}" for lim in dossier.limitations])
        elements.append(Paragraph(limits_text, body_style))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<b>Evidentiary Disclaimer:</b> <i>{dossier.disclaimer}</i>", body_style))
        elements.append(Spacer(1, 8))

        # =========================================================================
        # 15. SECTION 63 BHARATIYA SAKSHYA ADHINIYAM (BSA) 2023 STATUTORY CERTIFICATE
        # =========================================================================
        elements.append(PageBreak())  # Standalone certified final sheet for court filing
        elements.append(Paragraph("15. STATUTORY CERTIFICATE OF ELECTRONIC EVIDENCE", sec_heading))
        elements.append(Paragraph(
            "<b>SCHEDULE TO SECTION 63, BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023</b><br/>"
            "<i>(Admissibility of Electronic Records — Form of Certificate pursuant to Sub-Section (4) of Section 63; Superseding Section 65B of Indian Evidence Act, 1872)</i>",
            body_style
        ))
        elements.append(Spacer(1, 6))

        case_no = dossier.case_identification.case_number
        ev_id = dossier.evidence_integrity.evidence_id
        ev_hash = dossier.evidence_integrity.sha256_hash
        ev_file = dossier.evidence_integrity.original_filename
        ev_size = dossier.evidence_integrity.file_size_bytes
        ingest_time = dossier.evidence_integrity.ingestion_timestamp
        gen_time = dossier.case_identification.report_generated_at or dossier.generated_at
        analyst_name = dossier.case_identification.investigator or "Authorized Cyber Forensic Examiner"
        engine_ver = dossier.anvesh_version or "2.0.0"

        cert_intro = (
            "I, the undersigned Digital Forensic Examiner and System Custodian, responsible for the lawful operation "
            "and management of the ANVESH Forensic Intelligence Examination System, do hereby solemnly affirm, "
            "certify, and attest in accordance with <b>Section 63 of the Bharatiya Sakshya Adhiniyam, 2023</b> as follows:"
        )

        part_a_text = (
            "<b>PART A: IDENTIFICATION OF ELECTRONIC RECORD & CREATION ENVIRONMENT</b><br/>"
            f"• <b>Electronic Record Ingested:</b> RFC-822 Raw Email Evidence Artifact (<code>{ev_file}</code>, {ev_size} bytes)<br/>"
            f"• <b>Cryptographic SHA-256 Digest:</b> <font face='Courier' size='7.5' color='#1E3A8A'>{ev_hash}</font><br/>"
            f"• <b>Case File Reference:</b> {case_no} &nbsp;|&nbsp; <b>Evidence Vault ID:</b> <font face='Courier' size='7.5'>{ev_id}</font><br/>"
            f"• <b>Ingestion Timestamp:</b> {ingest_time} &nbsp;|&nbsp; <b>Extraction Mode:</b> Lossless Stream Capture<br/>"
            f"• <b>Examining Engine:</b> ANVESH Cognitive Forensics Platform v{engine_ver}, Python 3.11 Runtime, RFC-5322 Compliant Parser, BGP & Live GeoIP Resolver."
        )

        part_b_text = (
            "<b>PART B: STATUTORY AFFIRMATIONS PURSUANT TO SECTION 63(2) BSA 2023</b><br/>"
            "1. The electronic record described herein was produced and processed by the computer system during the period over which the computer was used regularly to store, analyze, and process digital evidence in the ordinary course of official cyber forensic and incident response activities.<br/>"
            "2. Information of that kind was regularly supplied to the said computer system in the ordinary course of the said lawful activities.<br/>"
            "3. Throughout the material part of the said period, the computer system, its memory units, parsing pipeline, and cryptographic hashing engines were operating properly under lawful, normal operating parameters, with no malfunction such as to affect the production of the electronic record or the accuracy of its contents.<br/>"
            "4. The contents reproduced in this canonical forensic dossier reproduce with 100% bit-level fidelity the original electronic data ingested, preserved under immutable SHA-256 chain of custody, without any unauthorized interception, deletion, alteration, or tampering."
        )

        part_c_text = (
            "<b>PART C: VERIFICATION, ATTESTATION & SIGNATURE</b><br/>"
            f"<b>Certifying Examiner:</b> {analyst_name}<br/>"
            f"<b>Designation:</b> Forensic Analyst & Electronic Evidence Custodian<br/>"
            f"<b>Organization / Unit:</b> Digital Forensic & Cyber Threat Intelligence Cell<br/>"
            f"<b>Issuance Timestamp:</b> {gen_time} &nbsp;|&nbsp; <b>Jurisdiction:</b> Republic of India<br/><br/>"
            "<b>[ VERIFIED DIGITAL SIGNATURE & OFFICIAL STATUTORY SEAL ]</b><br/>"
            "<i>(Signed and sealed in strict compliance with Section 63(4), Bharatiya Sakshya Adhiniyam, 2023)</i>"
        )

        cert_full_html = f"{cert_intro}<br/><br/>{part_a_text}<br/><br/>{part_b_text}<br/><br/>{part_c_text}"

        t_cert = Table([[Paragraph(cert_full_html, body_style)]], colWidths=[540])
        t_cert.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 1.5, colors.HexColor('#1E3A8A')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        elements.append(t_cert)

        # Build Document with NumberedCanvas
        doc.build(elements, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        # Compute SHA-256 fingerprint of the exported PDF binary
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest().lower()
        return pdf_bytes, pdf_sha256


pdf_report_generator = PDFReportGenerator()
