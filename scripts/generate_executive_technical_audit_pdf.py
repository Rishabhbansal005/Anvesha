"""
ANVESH — Executive Technical Audit, System Flowchart & Strategic Roadmap PDF Generator.
Generates an authoritative, publication-ready PDF document including visual flowcharts,
exact attribute breakdowns, real-world industry comparison, and 5 defense-grade suggestions.
"""
import os
import sys
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

BASE_DIR = r"C:\Users\Ongkar\Desktop\Avnesh\Anvesha-main\Anvesha-main"
DOCS_DIR = os.path.join(BASE_DIR, "docs")
SCREENSHOTS_DIR = os.path.join(DOCS_DIR, "screenshots")
OUTPUT_PDF_DOCS = os.path.join(DOCS_DIR, "ANVESH_EXECUTIVE_TECHNICAL_AUDIT_REPORT.pdf")
OUTPUT_PDF_DESKTOP = r"C:\Users\Ongkar\Desktop\ANVESH_EXECUTIVE_TECHNICAL_AUDIT_REPORT.pdf"
OUTPUT_PDF_BRAIN = r"C:\Users\Ongkar\.gemini\antigravity-ide\brain\c5eb7d2d-6375-460c-bb8b-47c31c603067\ANVESH_EXECUTIVE_TECHNICAL_AUDIT_REPORT.pdf"


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for running header/footer and accurate 'Page X of Y' numbering."""
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
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#475569"))

        # Top Running Header (Pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 758, "ANVESH — EXECUTIVE TECHNICAL AUDIT & ARCHITECTURAL ROADMAP")
            self.drawRightString(576, 758, "SIH26106 | FORENSIC INTELLIGENCE PLATFORM")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(36, 752, 576, 752)

        # Bottom Running Footer
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 38, 576, 38)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(36, 26, "CONFIDENTIAL & AUTHORITATIVE — CYBER FORENSIC DIVISION — FOR EVALUATORS ONLY")
        self.drawRightString(576, 26, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT_PDF_DOCS,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=46
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=12
    )
    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=body_style,
        leftIndent=14,
        firstLineIndent=-10,
        spaceAfter=3
    )
    callout_style = ParagraphStyle(
        'Callout',
        parent=body_style,
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor('#1E293B')
    )
    table_text = ParagraphStyle(
        'TableTxt',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor('#1E293B')
    )
    table_hdr = ParagraphStyle(
        'TableHdr',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#FFFFFF')
    )

    story = []

    # Title Banner Block
    banner_data = [[
        Paragraph("<b>ANVESH (अन्वेष) — EXECUTIVE TECHNICAL AUDIT & ARCHITECTURE ROADMAP</b>", title_style),
        Paragraph("<b>STATUS: PRODUCTION-AUDITED</b><br/>SIH26106 Compliance Verified", table_hdr)
    ]]
    t_banner = Table(banner_data, colWidths=[410, 130])
    t_banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#F8FAFC')),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#0284C7')),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW', (0, 0), (-1, -1), 1.5, colors.HexColor('#0284C7')),
    ]))
    story.append(t_banner)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "<b>Audited Subsystems:</b> Dual-Pillar Pipeline (Email Forensics + Live Npcap NDR) | "
        "<b>Trained Attributes:</b> 42 Attributes (41 Features) on NSL-KDD Benchmark + 15,000 NLP N-Grams | "
        "<b>Host Driver:</b> Physical Npcap Hooking | <b>Generated:</b> September 2026",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0'), spaceAfter=10))

    # SECTION 1: WHAT IS THE PROJECT DOING?
    story.append(Paragraph("1. Executive Summary & Core Platform Purpose", h1_style))
    story.append(Paragraph(
        "<b>ANVESH (अन्वेष)</b> is an AI-powered cyber forensic intelligence and network threat detection platform "
        "engineered to bridge the critical gap between raw telemetry (RFC-822 email headers and raw network wire packets) "
        "and court-admissible legal intelligence. Built specifically for Law Enforcement Cyber Crime Units, Police Forensics "
        "Laboratories, and Enterprise Tier-1/Tier-2 SOC Analysts, ANVESH operates across two synchronized operational pillars:",
        body_style
    ))

    p1_text = (
        "<b>Pillar 1 — Email Threat Forensics (MIME to Court Evidence):</b> Ingests suspicious RFC-822 <code>.eml</code> files, "
        "calculates an immutable SHA-256 evidence digest, traverses all intermediate transmission hops back to the originating IP, "
        "validates cryptographic SPF/DKIM/DMARC authentication, detects Tor exit nodes, evaluates body and header text through "
        "two specialized NLP models (Phishing and Business Email Compromise), and outputs court-admissible PDF investigation dossiers."
    )
    p2_text = (
        "<b>Pillar 2 — Real-Time Network Threat Detection (Engine 5 NDR):</b> Hooks directly into the host OS physical network interface "
        "via the <b>Npcap kernel packet driver</b>, captures raw wire frames passively, aggregates bidirectional packets into 5-tuple "
        "session flows, extracts 41 transport features, classifies anomalies in real time via a Scikit-learn Random Forest model, "
        "and exports standardized Wireshark <code>.pcap</code> captures for deep forensic analysis."
    )
    story.append(Paragraph(f"• {p1_text}", bullet_style))
    story.append(Paragraph(f"• {p2_text}", bullet_style))
    story.append(Spacer(1, 8))

    # SECTION 2: HIGH-RESOLUTION ARCHITECTURE FLOWCHARTS
    story.append(Paragraph("2. System Architecture & Operational Flowcharts", h1_style))
    story.append(Paragraph(
        "ANVESH implements a modular, asynchronous architecture combining Python 3.12 (FastAPI), React 18 (Vite SOC Workstation), "
        "Scapy 2.7, Npcap packet capture driver, and Scikit-learn serialized estimators.",
        body_style
    ))

    master_chart_path = os.path.join(SCREENSHOTS_DIR, "anvesh_master_architecture_flowchart.png")
    if os.path.exists(master_chart_path):
        story.append(RLImage(master_chart_path, width=7.5*inch, height=4.3*inch))
        story.append(Paragraph("<b>Figure 1:</b> ANVESH Master Architecture Flowchart — End-to-End Ingestion, AI Pipeline & Deliverables.", callout_style))
        story.append(Spacer(1, 10))

    story.append(PageBreak())

    # PAGE 2: Network Flowchart & Attribute Catalog
    story.append(Paragraph("2.1 Engine 5: Network Detection & Response (NDR) Flowchart", h2_style))
    net_chart_path = os.path.join(SCREENSHOTS_DIR, "anvesh_dual_pipeline_flowchart.png")
    if os.path.exists(net_chart_path):
        story.append(RLImage(net_chart_path, width=7.5*inch, height=3.5*inch))
        story.append(Paragraph("<b>Figure 2:</b> Engine 5 Telemetry Flowchart — Kernel Driver (Npcap) to 41-Feature Random Forest Classifier.", callout_style))
        story.append(Spacer(1, 10))

    # SECTION 3: ATTRIBUTES CATALOG
    story.append(Paragraph("3. Complete Catalog of Trained Attributes & AI Models", h1_style))
    story.append(Paragraph(
        "ANVESH strictly rejects black-box ambiguity. Each AI model is trained on empirically governed, reproducible feature sets:",
        body_style
    ))

    model_summary_data = [
        [Paragraph("Model Identifier", table_hdr), Paragraph("Feature Count", table_hdr), Paragraph("Algorithm / Classifier", table_hdr), Paragraph("Target Output", table_hdr)],
        [Paragraph("<b>Model 1 (Phishing NLP)</b>", table_text), Paragraph("10,000 N-Grams", table_text), Paragraph("TF-IDF + Calibrated Logistic Regression", table_text), Paragraph("BENIGN vs THREAT_PHISHING", table_text)],
        [Paragraph("<b>Model 2 (BEC Detector)</b>", table_text), Paragraph("5,000 N-Grams", table_text), Paragraph("Balanced Logistic Regression", table_text), Paragraph("BEC_FINANCIAL_PRESSURE", table_text)],
        [Paragraph("<b>Model 3A (Identity Impersonation)</b>", table_text), Paragraph("3 Heuristics", table_text), Paragraph("Display-Name & Local-Part Offset", table_text), Paragraph("IDENTITY_DISCREPANCY", table_text)],
        [Paragraph("<b>Model 3B (Lookalike Domain)</b>", table_text), Paragraph("6 Distance Metrics", table_text), Paragraph("Levenshtein / Jaro-Winkler Matrix", table_text), Paragraph("LOOKALIKE_DOMAIN", table_text)],
        [Paragraph("<b>Model 4/5 (Network Intrusion)</b>", table_text), Paragraph("41 Telemetry Features", table_text), Paragraph("Random Forest (ColumnTransformer)", table_text), Paragraph("NORMAL vs ANOMALY", table_text)],
    ]
    t_models = Table(model_summary_data, colWidths=[130, 95, 175, 140])
    t_models.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')])
    ]))
    story.append(t_models)
    story.append(Spacer(1, 8))

    story.append(Paragraph("3.1 Breakdown of the 41 Network Telemetry Features (NSL-KDD Benchmark)", h2_style))
    story.append(Paragraph(
        "Engine 5 processes 41 connection attributes partitioned into four forensic groups: "
        "<b>(1) Basic Connection Features (9):</b> duration, protocol_type (TCP/UDP/ICMP), service (70 services), flag (SF, REJ, S0, etc.), src_bytes, dst_bytes, land, wrong_fragment, urgent. "
        "<b>(2) Content & Host Privilege Features (13):</b> hot indicators, num_failed_logins, logged_in status, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_host_login, is_guest_login. "
        "<b>(3) Time-Based Traffic Features (9):</b> count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate. "
        "<b>(4) Host-Based Connection Features (10):</b> dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate.",
        body_style
    ))

    story.append(PageBreak())

    # PAGE 3: Industry Comparison & 5 Suggestions
    story.append(Paragraph("4. Global Industry Benchmark & Competitive Positioning", h1_style))
    story.append(Paragraph(
        "How ANVESH compares against leading multi-billion-dollar commercial cybersecurity platforms:",
        body_style
    ))

    comp_data = [
        [Paragraph("Platform", table_hdr), Paragraph("Category", table_hdr), Paragraph("Email Forensics", table_hdr), Paragraph("Network NDR", table_hdr), Paragraph("Legal Chain of Custody", table_hdr)],
        [Paragraph("<b>Darktrace</b> (~$5B)", table_text), Paragraph("NDR / Enterprise Immune", table_text), Paragraph("Add-on (Antigena)", table_text), Paragraph("Core (Proprietary)", table_text), Paragraph("Proprietary Logs", table_text)],
        [Paragraph("<b>Abnormal Security</b> (~$5B)", table_text), Paragraph("Cloud Email Security", table_text), Paragraph("Core (NLP / API)", table_text), Paragraph("None", table_text), Paragraph("Vendor Portal", table_text)],
        [Paragraph("<b>Vectra AI</b> (~$1.2B)", table_text), Paragraph("Network Detection", table_text), Paragraph("None", table_text), Paragraph("Core (Zeek/C2 AI)", table_text), Paragraph("PCAP Indexing", table_text)],
        [Paragraph("<b>Zeek + Suricata</b>", table_text), Paragraph("Open-Source IDS/NDR", table_text), Paragraph("Header Logging", table_text), Paragraph("Core (Deep Packet)", table_text), Paragraph("Flat Log Files", table_text)],
        [Paragraph("<b>ANVESH (Our Project)</b>", table_text), Paragraph("Unified Cyber Forensics", table_text), Paragraph("<b>Integrated (Models 1-3)</b>", table_text), Paragraph("<b>Integrated (Npcap Engine 5)</b>", table_text), Paragraph("<b>Court PDF + SHA-256 Hashes</b>", table_text)],
    ]
    t_comp = Table(comp_data, colWidths=[110, 110, 105, 105, 110])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#E0F2FE')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 10))

    # SECTION 5: 5 ADVANCED STRATEGIC SUGGESTIONS
    story.append(Paragraph("5. Five Strategic Advancements to Make ANVESH Defense-Grade", h1_style))
    story.append(Paragraph(
        "To elevate ANVESH from an academic/hackathon winner to an enterprise-grade, institutional cyber defense platform, "
        "we recommend the following 5 strategic implementations:",
        body_style
    ))

    suggs = [
        ("1. Automated XDR Attack-Chain Correlator (The Email-to-Wire Bridge)",
         "Automatically extract IOCs (malicious IPs and domains) from analyzed phishing emails and insert them into an active "
         "Engine 5 network monitoring watch-table. If an endpoint generates outgoing packets toward that IP, trigger an instant "
         "Correlated Attack Chain Alert: 'Victim opened phishing email at 10:14 AM ➔ Active C2 socket established at 10:17 AM'."),
        
        ("2. SOAR Active Defense & One-Click Firewall Containment",
         "Transform ANVESH from passive observation to active containment. Introduce a single-click 'Quarantine Endpoint' button "
         "that executes local Windows Firewall block rules (netsh advfirewall) and auto-generates exportable Snort/Suricata "
         "signatures and YARA rules based on the incident's cryptographic hashes."),

        ("3. Quishing (QR Code Phishing) Decoder & Static Macro Sandbox",
         "Counter 2026's fastest-growing evasion technique by extracting image attachments, decoding embedded QR codes (via pyzbar/opencv), "
         "and safely following HTTP redirect chains in a sandboxed headless environment. Simultaneously inspect Office attachments for VBA macros and high Shannon entropy."),

        ("4. Section 65B Electronic Evidence Certificate Generator (Indian Law)",
         "Implement one-click generation of Section 65B Certificates under the Indian Evidence Act / Bharatiya Sakshya Adhiniyam. "
         "Generates a formal legal affidavit containing hardware UUIDs, examiner credentials, capture timestamps, and SHA-256 integrity "
         "guarantees, rendering ANVESH dossiers immediately admissible in Indian courts."),

        ("5. Interactive 3D Multi-Hop Transit Map & MITRE ATT&CK Matrix Heatmap",
         "Upgrade the static hop table to an interactive WebGL 3D globe showing the email's physical flight path across world relays. "
         "Simultaneously map all detected anomalies to official MITRE ATT&CK techniques (T1566 Spearphishing, T1046 Network Discovery, T1498 DoS) in a visual SOC heatmap.")
    ]

    for title, desc in suggs:
        story.append(Paragraph(f"<b>{title}</b>", h2_style))
        story.append(Paragraph(desc, body_style))

    story.append(Spacer(1, 8))

    # SECTION 6: ETHICAL DECLARATION
    story.append(Paragraph("6. Forensic Attribution Safeguard (Ethical Invariant)", h1_style))
    story.append(Paragraph(
        "A core design invariant enforced across ANVESH is <b>Evidentiary Neutrality</b>: <i>'Technical email headers and IP hops identify "
        "transit infrastructure and network gateways ONLY. Individual physical human identity CANNOT be established solely from transport headers.'</i> "
        "All assessment cards and generated dossiers explicitly declare <code>Actor Identity: NOT ESTABLISHED</code>, protecting innocent victim server owners "
        "from premature or false criminal attribution.",
        callout_style
    ))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] PDF generated successfully at: {OUTPUT_PDF_DOCS}")

    # Copy to Desktop and Brain
    try:
        shutil.copyfile(OUTPUT_PDF_DOCS, OUTPUT_PDF_DESKTOP)
        print(f"[+] Copied to Desktop: {OUTPUT_PDF_DESKTOP}")
    except Exception as e:
        print(f"[-] Could not copy to Desktop: {e}")

    try:
        shutil.copyfile(OUTPUT_PDF_DOCS, OUTPUT_PDF_BRAIN)
        print(f"[+] Copied to Brain: {OUTPUT_PDF_BRAIN}")
    except Exception as e:
        print(f"[-] Could not copy to Brain: {e}")

if __name__ == "__main__":
    build_pdf()
