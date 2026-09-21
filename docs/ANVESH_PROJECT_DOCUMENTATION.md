# ANVESH (अन्वेष) — Comprehensive Project & Module Documentation
**Smart India Hackathon 2026 | Problem Statement SIH26106**  
*AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform*

---

## 1. Executive Description of the Project

**ANVESH (अन्वेष)** is a forensic-grade cyber intelligence platform engineered to ingest, deconstruct, analyze, and attribute suspicious emails. Built specifically for law enforcement agencies, Security Operations Centers (SOCs), and incident response analysts, ANVESH bridges the gap between raw RFC-822 message headers and actionable legal intelligence.

The system incorporates an immutable **SHA-256 evidence chain of custody**, a **4-tier specialized Machine Learning engine**, authoritative **BGP network telemetry**, and an **Explainable Signal Fusion Engine** that synthesizes technical findings into a court-admissible forensic PDF dossier.

---

## 2. Why This Project? (Problem Statement & Purpose)

### The Problem (`SIH26106`)
Modern email cybercrime exploits structural flaws in internet email protocols (SMTP/RFC-822):
1. **Business Email Compromise (BEC)**: Fraudsters use display-name spoofing and urgent financial coercion to divert bank wire transfers.
2. **Lookalike Domains (Typosquatting & Homoglyphs)**: Attacker domains visually imitate legitimate banking and government portals (e.g. `paypa1.com` mimicking `paypal.com` or `rnicrosoft.com` mimicking `microsoft.com`).
3. **Multi-Hop Relay Obfuscation**: Attackers route messages through Tor exit nodes, residential proxies, and bulletproof hosting to mask true origin IPs.
4. **False / Premature Attribution Risk**: Traditional automated tools falsely accuse server administrators, VPN providers, or compromised tenant owners whose infrastructure was merely abused during transit.

### The ANVESH Purpose & Solution
ANVESH provides **Zero-Fabrication** evidence analysis combining cryptographic validation, autonomous system lookups, explainable ML risk scoring, and an **Ethical Attribution Boundary**. It ensures legal admissibility while enforcing an invariant that network transit hops do not equal physical human identity.

---

## 3. Total Modules in the Project

The ANVESH platform consists of **7 Core Modules**:

```
                                  ANVESH CORE PLATFORM
                                           │
 ┌───────────────────────┬─────────────────┴─────────────────┬───────────────────────┐
 ▼                       ▼                                   ▼                       ▼
Module 1:               Module 2:                           Module 3:               Module 4:
RFC-822 Ingestion       Cryptographic Auth Matrix           Multi-Tier ML Engine    Signal Fusion & Scoring
& Hashing Ledger        (SPF / DKIM / DMARC)                (Models 1, 2, 3A, 3B)   (Explainable Risk)
 │                       │                                   │                       │
 └───────────────────────┼───────────────────────────────────┴───────────────────────┘
                         ▼
 ┌───────────────────────┼───────────────────────────────────┐
 ▼                       ▼                                   ▼
Module 5:               Module 6:                           Module 7:
BGP Telemetry &         Web SOC Workstation &               Mobile Incident Response
Threat Intelligence     Court-Ready PDF Engine              Companion Application
```

---

## 4. Technical Working of Each Module

### Module 1: RFC-822 Ingestion & Hashing Ledger
- **Role**: Entry point for all raw email payloads (`.eml` files or raw header strings).
- **Working Mechanism**:
  - Immediately computes the **SHA-256 cryptographic hash** of the raw payload upon receipt to guarantee an unalterable evidence baseline.
  - Parses MIME parts, MIME boundaries, body text, HTML components, attachment metadata, and all transport headers (`From`, `To`, `Subject`, `Message-ID`, `Reply-To`, `Return-Path`).
  - Traverses the chronological stack of `Received:` header hops from perimeter receiver back to the probable originating IP gateway.
- **Output**: Structured JSON object containing sanitized MIME trees, evidence hashes, and candidate origin IPs.

### Module 2: Cryptographic Authentication Matrix
- **Role**: Validates email transport authenticity and domain ownership protocols.
- **Working Mechanism**:
  - **SPF (Sender Policy Framework)**: Checks whether the sending IP is authorized by the domain's DNS SPF TXT record.
  - **DKIM (DomainKeys Identified Mail)**: Verifies cryptographic public-key RSA/Ed25519 digital signatures in the `DKIM-Signature` header.
  - **DMARC (Domain-based Message Authentication)**: Enforces alignment policy (`p=reject`, `p=quarantine`, or `p=none`) between `Header From` and SPF/DKIM domains.
- **Output**: Cryptographic pass/fail matrix highlighting active tampering vs. domain misconfiguration.

### Module 3: Multi-Tier Machine Learning Subsystem
- **Role**: Performs specialized behavioral, linguistic, and lexical risk classification across 4 dedicated models.
- **Working Mechanism**:
  - **Model 1 (Phishing NLP Vector Classifier)**: Uses TF-IDF vectorization and calibrated Logistic Regression to detect credential harvesting lexicons and psychological urgency phrases.
  - **Model 2 (BEC & Financial Coercion Detector)**: Scans text for wire transfer demands, executive impersonation, and payment rerouting language.
  - **Model 3A (Identity Impersonation Engine)**: Evaluates discrepancies between sender display names and actual mailbox local-parts.
  - **Model 3B (Lookalike Domain & Homoglyph Engine)**: Uses a Levenshtein and Jaro-Winkler metric matrix to catch character substitutions (e.g., `rn` ➔ `m`, `1` ➔ `l`, `0` ➔ `o`).
- **Output**: Vector probability scores (0.0 to 1.0) and identified threat vectors per model.

### Module 4: Forensic Signal Fusion & Risk Scoring Engine
- **Role**: Synthesizes all independent ML models, cryptographic results, and IP indicators into a single explainable score.
- **Working Mechanism**:
  - Normalizes weighted category contributions (Content, Identity, Infrastructure, Cryptographic Auth, Threat Intel).
  - Calculates a **0 to 100 Threat Score** and categorizes risk (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Evaluates signal contradictions (e.g., valid DKIM pass vs. phishing language) and outputs explicit confidence rationales.
  - Enforces the **Attribution Boundary Invariant**: Flags `Actor Identity: NOT ESTABLISHED` to ensure legal neutrality.
- **Output**: Complete Explainable Risk Dossier JSON.

### Module 5: BGP Telemetry & Threat Intelligence Module
- **Role**: Resolves IP network infrastructure, routing topology, and proxy indicators.
- **Working Mechanism**:
  - Resolves Autonomous System Numbers (ASN), BGP network prefixes, ISP organization names, and geographic locations.
  - Differentiates RFC 1918 private IPs from public routable IPs.
  - Queries active Tor exit node registries and proxy databases to flag anonymized relay transit.
- **Output**: Network intelligence profile including ASN, ISP, country, and proxy flags.

### Module 6: Web SOC Workstation & Court-Ready PDF Engine
- **Role**: Primary user workstation for security analysts and forensic investigators.
- **Working Mechanism**:
  - Built with **React 18 + Vite + Tailwind CSS** in a modern dark SOC workstation theme.
  - Provides drag-and-drop file ingestion, dynamic threat gauges, cases ledger, activity timeline, and campaign graphs.
  - Features a ReportLab PDF generator that creates cryptographically sealed, formal court dossiers containing SHA-256 evidence verification cards.
- **Output**: Interactive web interface and downloadable PDF/JSON court reports.

### Module 7: Mobile Incident Response Companion Module
- **Role**: On-call incident response app for mobile devices.
- **Working Mechanism**:
  - Built using **React Native + Expo SDK 52**.
  - Syncs real-time alert triage, case adjudication status, and quick IP/Domain indicator lookups for security teams on the go.
- **Output**: Native mobile interface for Android and iOS.

---

## 5. 6 Team Roles & Responsibilities

| Role Number | Role Title | Key Team Responsibilities |
| :---: | :--- | :--- |
| **Role 1** | **Lead Cyber Forensic & Security Architect** | Designed RFC-822 header parsing logic, defined evidentiary invariants, established legal attribution boundaries, and architected court-admissible PDF dossier structures. |
| **Role 2** | **Backend Engine Specialist** | Developed the FastAPI core monolith, designed Pydantic v2 data schemas, implemented REST API endpoints, and built database ORM session management. |
| **Role 3** | **AI/ML Security Researcher** | Trained, validated, and serialized the 4 ML models (Phishing NLP, BEC Detector, Identity Impersonation, and Lookalike Domain Levenshtein matrix). |
| **Role 4** | **Frontend Lead / UX Engineer** | Designed the React 18 + Vite SOC workstation, built interactive threat score gauges, header hop timeline visualizations, and dark-theme Tailwind UI components. |
| **Role 5** | **Mobile Systems Engineer** | Developed the React Native + Expo companion application, implemented cross-platform navigation, mobile alert triage cards, and API synchronization. |
| **Role 6** | **DevOps & Database Administrator** | Configured Supabase PostgreSQL schemas, created Row-Level Security (RLS) policies, built local SQLite fallback session handlers, and managed environment variables. |

---

## 6. Future Vision & Project Roadmap

```
                                ANVESH FUTURE ROADMAP
                                          │
       ┌──────────────────────────────────┼──────────────────────────────────┐
       ▼                                  ▼                                  ▼
Phase 1 (Current)                Phase 2 (6 Months)                 Phase 3 (12 Months)
• SIH26106 Monolith Core         • Registrar Subpoena Automation    • Hardware Security Module (HSM)
• 4-Tier ML Engine               • Graph Database (Neo4j)           • Enterprise SIEM / SOAR Connectors
• Web & Mobile Apps              • LLM Forensic Assistant           • ISP NetFlow Correlation Engine
```

1. **Automated Registrar Subpoena & LER Integration**:
   - Integration with Law Enforcement Request (LER) portals of top ccTLD/gTLD registrars to auto-generate subpoena drafts for newly registered lookalike domains.

2. **Graph Database Campaign Correlator (Neo4j)**:
   - Upgrading relational correlation to a full graph database to map complex multi-million message criminal syndicates across global subnets.

3. **LLM-Assisted Analyst Co-Pilot**:
   - Integrating a fine-tuned open-weights LLM co-pilot for automated natural language incident summaries and recommended mitigation playbooks.

4. **Hardware Security Module (HSM) Cryptographic Signing**:
   - Signing generated PDF dossiers with hardware-backed digital certificate keys to guarantee complete evidentiary tamper-proofing in legal courtrooms.
