<div align="center">

# 🔍 ANVESH
### AI-Powered Email Threat Detection & Forensic Analysis System

[![SIH 2026](https://img.shields.io/badge/SIH%202026-Problem%20SIH26106-blue?style=for-the-badge)](https://www.sih.gov.in/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Team: Heuristic Horizon | SIH Problem Code: SIH26106**

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [ML Models](#-ml-models) · [API Docs](#-api-reference) · [Datasets](#-datasets) · [References](#-references)

</div>

---

## 📌 What is ANVESH?

ANVESH is an **indigenous, AI-powered email security and digital forensics platform** built for India's critical infrastructure — Government agencies, BFSI, and Enterprises.

It analyzes suspicious emails in **under 1.2 seconds**, assigns a 0–100 risk score, and generates **court-admissible forensic reports** — all while keeping data 100% within Indian servers (DPDP Act 2023 compliant).

> **Problem it solves:** India reported **29.44 lakh cyber incidents in 2024** (CERT-In). Over **91% of cyberattacks begin with a malicious email.** Existing solutions are foreign, expensive, and send data offshore.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧠 **5-Layer AI Detection** | Parallel ML models detect Phishing, BEC, Lookalike Domains, Network Anomalies, and deep semantic threats |
| ⚡ **< 1.2 Second Analysis** | Async FastAPI backend with hierarchical inference (lightweight models handle 90% of traffic) |
| 🗺️ **Hop Flow Graph** | Visual email relay trace with attacker IP geolocation on an interactive map |
| 📋 **Forensic PDF Report** | SHA-256 sealed, court-admissible dossier compliant with BSA 2023 Section 63 |
| 🏛️ **MITRE ATT&CK Tagging** | Every threat automatically tagged with its ATT&CK technique code (T1566, T1598, etc.) |
| 📊 **Campaign Intelligence** | Clusters multiple emails by shared relay infrastructure to detect coordinated attacks |
| 📁 **Case Management** | Full analyst workflow — OPEN → UNDER_REVIEW → RESOLVED with evidence chain |
| 🔒 **Zero Data Storage** | Ephemeral in-memory parsing — raw emails never written to disk (DPDP compliant) |
| 🇮🇳 **Atmanirbhar Bharat** | 100% indigenous stack — no foreign gateways, no offshore data transfer |

---

## 🏗️ Architecture

```
+------------------------------------------------------------------+
|                          ANVESH PLATFORM                         |
+------------------+---------------------------+-------------------+
|    LAYER 1       |        LAYER 2            |     LAYER 3       |
|   Ingestion      |    AI Inference Engine    |   Forensics       |
|                  |                           |                   |
|  .eml Upload     | Model 1: Phishing         | Hop Flow Graph    |
|  RFC-822 Parse   | Model 2: BEC              | GeoIP Trace       |
|  SHA-256 Hash    | Model 3: Lookalike Domain | Campaign Cluster  |
|  SPF/DKIM/DMARC  | Model 4: Network Intrusion| PDF Dossier       |
|  Validation      | Model 5: RoBERTa NLP      | Case Management   |
+------------------+---------------------------+-------------------+
```

**Tech Stack:**

| Layer | Technology | Purpose |
|---|---|---|
| **Backend API** | Python 3.12 + FastAPI + Uvicorn | Async REST API engine |
| **ML Engine** | Scikit-learn + HuggingFace RoBERTa | 5 parallel threat detection models |
| **Email Parsing** | Python email + dnspython | RFC-822 header + DNS validation |
| **Network Layer** | Scapy + MaxMind GeoIP2 | Packet capture + IP geolocation |
| **Frontend** | React 19 + TypeScript + Vite | Investigation dashboard |
| **Database** | SQLAlchemy + SQLite (dev) / PostgreSQL (prod) | Case & campaign storage |
| **PDF Reports** | ReportLab | Court-admissible forensic dossier |
| **Auth** | PyJWT | Secure analyst authentication |

---

## 📁 Project Structure

```
ANVESH/
├── backend/                        # FastAPI backend engine
│   ├── app/
│   │   ├── api/v1/endpoints/       # REST API routes
│   │   ├── services/               # Core business logic
│   │   │   ├── risk_engine.py              # 0-100 threat score
│   │   │   ├── forensic_fusion_service.py  # Signal aggregation
│   │   │   ├── campaign_service.py         # Attack campaign clustering
│   │   │   ├── scapy_network_service.py    # Email hop trace
│   │   │   ├── lookalike_service.py        # Domain impersonation
│   │   │   ├── pdf_report_generator.py     # Forensic PDF export
│   │   │   └── case_workflow_service.py    # Case management
│   │   ├── models/                 # SQLAlchemy database models
│   │   └── schemas/                # Pydantic request/response schemas
│   ├── requirements.txt
│   └── run.py
│
├── web/                            # React 19 frontend dashboard
│   └── src/
│       ├── pages/
│       │   ├── InvestigationWorkspace.tsx  # Core analysis UI
│       │   ├── IntelligencePage.tsx        # Threat intelligence view
│       │   └── CasesPage.tsx              # Case management UI
│       └── components/
│           ├── investigation/      # HopFlowGraph, ForensicReport
│           ├── evaluation/         # ModelEvaluationViewer
│           └── network/            # Network telemetry components
│
├── ml/                             # Machine Learning pipeline
│   ├── models/                     # Trained .joblib model artifacts
│   │   ├── phishing_baseline_v1/
│   │   ├── bec_baseline_v1/
│   │   ├── lookalike_domain_v1/
│   │   └── network_intrusion_v1/
│   ├── training/                   # Model training scripts
│   ├── datasets/                   # Dataset governance & provenance
│   └── evaluation/                 # Evaluation charts & metrics
│
├── docs/                           # Extended documentation
├── start_app.bat                   # One-click Windows startup
└── .env.example                    # Environment variable template
```

---

## 🤖 ML Models

ANVESH runs **5 AI models in parallel**, each specializing in a different threat vector:

| Model | Type | Task | Dataset |
|---|---|---|---|
| `phishing_baseline_v1` | TF-IDF + Logistic Regression | Phishing email detection | [Zenodo IEEE 2024](https://zenodo.org/records/8339691) · [Nazario](https://monkey.org/~jose/phishing/) |
| `bec_baseline_v1` | TF-IDF + Logistic Regression | Business Email Compromise | [Enron Corpus](https://www.cs.cmu.edu/~enron/) |
| `lookalike_domain_v1` | Random Forest (10 features) | Typosquat / homoglyph domain | Levenshtein + Jaro-Winkler string features |
| `network_intrusion_v1` | Random Forest (41 features) | Email relay anomaly detection | [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html) |
| `roberta_transformer` | HuggingFace RoBERTa fine-tuned | Deep semantic NLP analysis | [RoBERTa Base](https://huggingface.co/roberta-base) |

> **Inference Strategy:** Lightweight Scikit-learn models handle 90% of traffic in milliseconds. RoBERTa is invoked only for borderline cases — keeping average latency under 1.2 seconds.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/Rishabhbansal005/Anvesha.git
cd Anvesha
```

### 2. Set Up Environment Variables

```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

### 3. Start the Backend (Terminal 1)

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Backend:** http://localhost:8000
- **Swagger API Docs:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/api/v1/health

### 4. Start the Web Dashboard (Terminal 2)

```bash
cd web
npm install
npm run dev
```

- **Dashboard:** http://localhost:5173

### 5. One-Click Windows Startup

```powershell
.\start_app.bat
```

---

## 🔑 Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Required
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///./anvesh_dev.db

# Optional - Enhanced Threat Intelligence
MAXMIND_ACCOUNT_ID=your-maxmind-id
MAXMIND_LICENSE_KEY=your-maxmind-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/health` | GET | System health check |
| `/api/v1/emails/analyze` | POST | Submit `.eml` file for full analysis |
| `/api/v1/emails/{id}/report` | GET | Get full forensic JSON report |
| `/api/v1/campaigns/` | GET | List detected attack campaigns |
| `/api/v1/cases/` | GET / POST | Manage analyst cases |
| `/api/v1/cases/{id}/status` | PATCH | Update case workflow status |

Full interactive documentation: **http://localhost:8000/docs**

---

## 🗄️ Datasets

| Dataset | Source | License |
|---|---|---|
| Phishing Email Curated Datasets (IEEE 2024) | [zenodo.org/records/8339691](https://zenodo.org/records/8339691) | Open Research |
| Jose Nazario Phishing Archive | [monkey.org/~jose/phishing](https://monkey.org/~jose/phishing/) | CC BY 4.0 |
| CMU Enron Email Dataset | [cs.cmu.edu/~enron](https://www.cs.cmu.edu/~enron/) | FERC Public Record |
| NSL-KDD Network Intrusion Dataset | [unb.ca/cic/datasets/nsl](https://www.unb.ca/cic/datasets/nsl.html) | Open Research |
| RoBERTa Base Model | [huggingface.co/roberta-base](https://huggingface.co/roberta-base) | MIT |

> **Data Governance:** SHA-256 cryptographic deduplication. 12,833 unique samples across 4-tier governance (Train / Validation / Test / Challenge).

---

## 📊 Performance Metrics

| Metric | Value |
|---|---|
| Average Analysis Latency | **< 1.2 seconds** per email |
| Phishing Detection Accuracy | **100%** (validation corpus) |
| Network Intrusion F1 Score | **98.98%** |
| Lookalike Domain F1 Score | **80%** (adversarial test set) |
| SOC Triage Time Saved | **92%** (25 min → < 1.2 sec) |
| Training Corpus Size | **12,833 unique samples** |

---

## 🛡️ MITRE ATT&CK Coverage

| ATT&CK Code | Technique | Detected By |
|---|---|---|
| T1566 | Phishing | Model 1 — Phishing Baseline |
| T1566.001 | Spear Phishing via Link | Model 1 + Model 5 (RoBERTa) |
| T1566.002 | Spear Phishing via Attachment | Model 1 + Model 5 |
| T1598 | Lookalike Domain Impersonation | Model 3 — Lookalike Domain |
| T1078 | Valid Account Compromise (BEC) | Model 2 — BEC Baseline |
| T1071 | Network Communication Anomaly | Model 4 — Network Intrusion |

---

## ⚖️ Legal & Compliance

| Standard | How ANVESH Complies |
|---|---|
| **DPDP Act 2023** | Zero raw email storage — ephemeral in-memory parsing only |
| **BSA 2023 (Section 63)** | SHA-256 integrity hashing for court-admissible electronic evidence |
| **MITRE ATT&CK** | All threats tagged with standardized ATT&CK technique codes |
| **NIST SP 800-177r1** | SPF, DKIM, DMARC validation per trustworthy email standard |

---

## 📚 References

**Research Papers**
- Liu et al. (2019). RoBERTa. https://arxiv.org/abs/1907.11692
- Vaswani et al. (2017). Attention Is All You Need. https://arxiv.org/abs/1706.03762
- Champa, Rabbi & Zibran (2024). Phishing Email Curated Datasets. https://zenodo.org/records/8339691
- Salloum et al. (2022). Phishing Detection using ML. https://www.mdpi.com/2079-9292/11/20/3360

**Government & Standards**
- CERT-In: https://www.cert-in.org.in
- National Cyber Crime Portal (I4C): https://cybercrime.gov.in
- MITRE ATT&CK: https://attack.mitre.org
- NIST SP 800-177r1: https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final
- DPDP Act 2023: https://www.meity.gov.in/data-protection-framework
- Bharatiya Sakshya Adhiniyam 2023: https://legislative.gov.in/bharatiya-sakshya-adhiniyam-2023/

---

## 👥 Team

**Team Name:** Heuristic Horizon
**Competition:** Smart India Hackathon 2026
**Problem Code:** SIH26106

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <strong>Built with ❤️ for Bharat | Atmanirbhar Cybersecurity</strong><br>
  <sub>ANVESH — Investigate. Detect. Protect.</sub>
</div>
