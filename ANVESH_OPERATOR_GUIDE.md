# ANVESH — Master Operator Manual & System Guide
**AI-Powered Email Threat Detection, GeoLocation & Cyber Forensic Intelligence Platform**  
**Smart India Hackathon (SIH) Problem Statement:** `SIH26106`  
**System Version:** `2.0.0-workspace` | **Status:** Production-Ready Modular Monolith

---

## Table of Contents
1. [What ANVESH Is](#1-what-anvesh-is)
2. [Architecture Map](#2-architecture-map)
3. [Prerequisites & System Requirements](#3-prerequisites--system-requirements)
4. [Project Folder Structure](#4-project-folder-structure)
5. [Environment Configuration & Variables](#5-environment-configuration--variables)
6. [Starting Database & Backend Dependencies](#6-starting-database--backend-dependencies)
7. [Starting the FastAPI Backend](#7-starting-the-fastapi-backend)
8. [Starting the Web Frontend](#8-starting-the-web-frontend)
9. [Starting the Mobile Application](#9-starting-the-mobile-application)
10. [Connecting Web Frontend → Backend](#10-connecting-web-frontend--backend)
11. [Connecting Mobile App → Backend (LAN & Tunneling)](#11-connecting-mobile-app--backend-lan--tunneling)
12. [Authentication & Analyst Roles](#12-authentication--analyst-roles)
13. [Uploading an Email (RFC-822 / .EML)](#13-uploading-an-email-rfc-822--eml)
14. [Running an Investigation](#14-running-an-investigation)
15. [Reading and Interpreting Results](#15-reading-and-interpreting-results)
16. [Cases & Investigation Management](#16-cases--investigation-management)
17. [Alerts Triage](#17-alerts-triage)
18. [Campaigns & Threat Actor Infrastructure](#18-campaigns--threat-actor-infrastructure)
19. [Threat Intelligence & External IOC Lookups](#19-threat-intelligence--external-ioc-lookups)
20. [Lookalike Domain Analysis (Model 3B)](#20-lookalike-domain-analysis-model-3b)
21. [Identity Impersonation Detection (Model 3A)](#21-identity-impersonation-detection-model-3a)
22. [Business Email Compromise (BEC) Analysis (Model 2)](#22-business-email-compromise-bec-analysis-model-2)
23. [Disposable Email Intelligence (Phase 12.5)](#23-disposable-email-intelligence-phase-125)
24. [Forensic Signal Fusion (Phase 9B)](#24-forensic-signal-fusion-phase-9b)
25. [Attribution Assessment & Non-Attribution Invariant](#25-attribution-assessment--non-attribution-invariant)
26. [Evidence Gaps & Prescriptive Guidance](#26-evidence-gaps--prescriptive-guidance)
27. [Case Workflow State Machine](#27-case-workflow-state-machine)
28. [Analyst Decision Management](#28-analyst-decision-management)
29. [Forensic Dossier Report Compilation](#29-forensic-dossier-report-compilation)
30. [PDF Export (Court-Ready Dossier)](#30-pdf-export-court-ready-dossier)
31. [Canonical JSON Export](#31-canonical-json-export)
32. [Chain of Custody Ledger](#32-chain-of-custody-ledger)
33. [Evidence Cryptographic Integrity (SHA-256)](#33-evidence-cryptographic-integrity-sha-256)
34. [The 8 SIH Demo Scenarios](#34-the-8-sih-demo-scenarios)
35. [Mobile Application Workflow](#35-mobile-application-workflow)
36. [Android APK Generation & Deployment](#36-android-apk-generation--deployment)
37. [Operator Troubleshooting Guide](#37-operator-troubleshooting-guide)
38. [Clean Shutdown Procedure](#38-clean-shutdown-procedure)
39. [Demo Reset Procedure](#39-demo-reset-procedure)
40. [Final SIH Demo Operator Checklist](#40-final-sih-demo-operator-checklist)

---

## 1. What ANVESH Is
**ANVESH** (अन्वेषण — *Forensic Investigation*) is a specialized cyber forensic intelligence platform engineered specifically for law enforcement, SOC tier-2/3 analysts, and cyber defense cells responding to sophisticated email-borne attacks.

Unlike generic spam or phishing filters, ANVESH treats every email message as **tamper-evident digital legal evidence**. It performs deep RFC-822 transport hop reconstruction, multi-tier machine learning classification, homoglyph and lookalike detection, campaign infrastructure correlation, and deterministic cross-modal signal fusion, producing court-admissible forensic dossiers with strict chain of custody and cryptographic SHA-256 verification.

---

## 2. Architecture Map

```text
                                  ANVESH ARCHITECTURE
                                  ===================

      +-------------------------+                 +-------------------------+
      |      Web Dashboard      |                 |   Mobile Application    |
      | (React 19 + Vite + CSS) |                 |  (Expo SDK 52 + RN 76)  |
      |   http://localhost:5173 |                 |   Android / iOS / LAN   |
      +------------+------------+                 +------------+------------+
                   |                                           |
                   | REST API (HTTP / JSON / Multipart)        |
                   +---------------------+---------------------+
                                         |
                                         v
                         +-------------------------------+
                         |     FastAPI Backend Engine    |
                         |   Uvicorn (Port 8000 / ASGI)  |
                         +---------------+---------------+
                                         |
        +--------------------------------+--------------------------------+
        |                                |                                |
        v                                v                                v
+----------------+              +------------------+             +-----------------+
| Forensic Core  |              |    ML Engines    |             |  Storage Layer  |
| & Fusion       |              |                  |             |                 |
| - RFC-822      |              | - Model 1 Phish  |             | - Supabase      |
| - Auth (SPF,   |              | - Model 2 BEC    |             |   (PostgreSQL   |
|   DKIM, DMARC) |              | - Model 3A Ident |             |   + PostgREST)  |
| - Transport Hop|              | - Model 3B Look- |             | - Local SQLite  |
|   Traversal    |              |   alike Domain   |             |   Fallback      |
| - Evidence Gap |              | - Disposable     |             |   (anvesh_dev)  |
| - Custody Chain|              |   Classifier     |             |                 |
+----------------+              +------------------+             +-----------------+
```

---

## 3. Prerequisites & System Requirements

### Operator Machine:
- **Operating System:** Windows 10/11 64-bit, macOS, or Linux.
- **Python:** Python 3.12 installed and registered in `PATH` (verify via `python --version` or `py -3.12 --version`).
- **Node.js:** Node.js LTS (v20+ or v22+ verified; tested on `v22.18.0`).
- **Package Managers:** `npm` (v10+) and `pip`.
- **Expo & EAS:** `@expo/cli` and `eas-cli` (v23.2+ installed globally for Android APK builds).
- **Network Access:** TCP port `8000` (Backend FastAPI) and TCP port `5173` (Vite Web UI) available.

---

## 4. Project Folder Structure

```text
SIH2026/
├── backend/                        # FastAPI Application
│   ├── app/
│   │   ├── api/v1/                 # Endpoints (emails, cases, alerts, intelligence, campaigns)
│   │   ├── core/                   # config.py, constants.py, security headers
│   │   ├── database/               # session.py, supabase_client.py, base.py
│   │   ├── models/                 # SQLAlchemy & Pydantic models
│   │   ├── schemas/                # Data transfer objects
│   │   └── services/               # Forensic fusion, ML classifiers, reports, campaigns
│   ├── ml_models/                  # Serialized ML artifacts (.pkl)
│   ├── tests/                      # Automated test suite (223 tests)
│   │   └── fixtures/sih_demo/      # The 9 official SIH demo EML fixtures
│   ├── requirements.txt            # Python dependencies
│   └── run.py                      # Production ASGI runner
├── web/                            # React 19 + Vite Frontend
│   ├── public/brand/               # Official ANVESH brand marks & logos
│   ├── src/
│   │   ├── components/             # Layout (TopBar), forensic cards, tabs
│   │   ├── context/                # ThemeContext (dark/light), AuthContext
│   │   ├── constants/              # Navigation, color tokens, API base URL
│   │   └── App.tsx                 # Master single-page application router
│   ├── package.json
│   └── vite.config.ts
├── mobile/                         # React Native (Expo) Companion App
│   ├── assets/brand/               # Official ANVESH square app icon
│   ├── src/
│   │   ├── screens/                # HomeScreen, CasesScreen, AlertsScreen, etc.
│   │   └── constants/              # API URL resolution, colors, status codes
│   ├── app.json                    # Expo config (package: com.anvesh.mobile)
│   ├── eas.json                    # EAS build profiles (including preview APK)
│   └── package.json
├── ml/                             # ML training pipelines, datasets, notebooks
├── supabase/                       # Database migrations (PostgreSQL schemas)
├── docs/                           # Architectural specifications
└── README.md
```

---

## 5. Environment Configuration & Variables

ANVESH reads configuration from `.env` files located in the project root, `backend/.env`, `web/.env`, and `mobile/.env`.

> [!IMPORTANT]
> **Strict Operational Security:** Never commit secret keys or expose credentials. Client applications (Web & Mobile) only use client-safe endpoints and publishable tokens.

### Configuration Reference Matrix:

| Variable | Purpose | Used By | Required | Default / Fallback |
| :--- | :--- | :--- | :---: | :--- |
| `ENVIRONMENT` | Defines deployment environment (`development` / `production`) | Backend | Yes | `development` |
| `DEBUG` | Enables verbose diagnostic output | Backend | Yes | `True` |
| `DATABASE_URL` | SQLAlchemy connection URI | Backend | Yes | `sqlite:///./anvesh_dev.db` |
| `SUPABASE_URL` | Supabase PostgREST endpoint | Backend / Web / Mobile | Yes | Remote project URL |
| `SUPABASE_SECRET_KEY` | Backend service-role key for table persistence | Backend Only | Yes | Injected via `.env` |
| `SUPABASE_PUBLISHABLE_KEY` | Client-side anonymous Supabase access | Web / Mobile | Yes | Injected via `.env` |
| `VITE_API_BASE_URL` | Web client backend target | Web | Yes | `http://localhost:8000/api/v1` |
| `EXPO_PUBLIC_API_BASE_URL` | Mobile client backend target (LAN IPv4) | Mobile | Yes | `http://<PC-LAN-IP>:8000/api/v1` |
| `VIRUSTOTAL_API_KEY` | External domain/URL intelligence lookups | Backend | No | Graceful degradation if empty |
| `ABUSEIPDB_API_KEY` | External IP reputation lookups | Backend | No | Graceful degradation if empty |
| `SAFE_BROWSING_API_KEY` | Google Safe Browsing URL checks | Backend | No | Graceful degradation if empty |

---

## 6. Starting Database & Backend Dependencies

ANVESH uses a resilient dual-database design:
1. **Primary Database:** Supabase PostgreSQL over PostgREST. All tables, foreign keys, and RLS policies are deployed via `supabase/migrations/`.
2. **Local Fallback:** SQLite database (`anvesh_dev.db`) initialized automatically on startup if PostgreSQL is offline, ensuring zero demo disruptions.

To verify database readiness:
```powershell
# Verify backend can reach Supabase
& "C:\Program Files\Python312\python.exe" -c "from app.database.supabase_client import supabase; print('Supabase Ping:', supabase.ping())"
```
Output must read: `Supabase Ping: True`.

---

## 7. Starting the FastAPI Backend

### Terminal 1 — Backend Startup:
```powershell
cd "c:\Users\Rishabh Bansal\OneDrive\Desktop\Razorpay Buildathon\SIH2026\backend"
& "C:\Program Files\Python312\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Expected Output:
```text
INFO:     Will watch for changes in ['...']
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started re-loader process [...]
INFO:     Started server process [...]
INFO:     Waiting for application startup.
INFO:PROJECT_NAME:[STARTUP] Creating PostgreSQL/SQLite database tables...
INFO:PROJECT_NAME:[STARTUP] Database tables verified successfully.
INFO:     Application startup complete.
```

- **Backend Base URL:** `http://localhost:8000`
- **Interactive Swagger Docs:** `http://localhost:8000/docs`
- **Health Verification Endpoint:** `http://localhost:8000/api/v1/health`

---

## 8. Starting the Web Frontend

### Terminal 2 — Web Frontend Startup:
```powershell
cd "c:\Users\Rishabh Bansal\OneDrive\Desktop\Razorpay Buildathon\SIH2026\web"
npm run dev
```

### Expected Output:
```text
  VITE v8.2.2  ready in 410 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

Open `http://localhost:5173/` in any modern browser (Chrome, Edge, Firefox, Safari).

---

## 9. Starting the Mobile Application

### Terminal 3 — Mobile Application Startup:
```powershell
cd "c:\Users\Rishabh Bansal\OneDrive\Desktop\Razorpay Buildathon\SIH2026\mobile"
npx expo start
```

### Modes:
- **LAN Mode (Default):** Accessible to physical phones on the same Wi-Fi network.
- **Tunnel Mode (If Wi-Fi isolation is enabled):** `npx expo start --tunnel`
- **Android Emulator:** Press `a` inside the terminal window.
- **Web Preview:** Press `w` to launch React Native Web in browser.

---

## 10. Connecting Web Frontend → Backend
The web frontend connects directly to `http://localhost:8000/api/v1` via standard CORS-enabled fetch calls.
- In the top right corner of the web header, look for the **`• SUPABASE LIVE`** green badge.
- When active, all forensic analyses, alerts, and campaign nodes are read and written to the live datastore.

---

## 11. Connecting Mobile App → Backend (LAN & Tunneling)

> [!WARNING]
> A physical Android phone cannot reach your PC using `localhost`. On a physical phone, `localhost` refers to the mobile device itself.

### Procedure for Real Android Phone Connectivity:
1. Determine your PC's local network IPv4 address:
   ```powershell
   ipconfig
   # Look for IPv4 Address (e.g., 192.168.1.5)
   ```
2. Verify that `mobile/.env` contains your PC's IPv4 address:
   ```env
   EXPO_PUBLIC_API_BASE_URL=http://192.168.1.5:8000/api/v1
   ```
3. Allow port `8000` through the Windows Defender Firewall:
   ```powershell
   New-NetFirewallRule -DisplayName "ANVESH Backend Port 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
   ```
4. Verify from the phone's browser: Navigate to `http://192.168.1.5:8000/api/v1/health`. It will return `{"status": "HEALTHY", ...}`.

---

## 12. Authentication & Analyst Roles
ANVESH enforces structured analyst role tracking for evidence custody:
- **Default Analyst Persona:** `SOC Senior Analyst`
- **Analyst ID:** `analyst_usr_902`
- **Official Handle:** `analyst@anvesh.gov.in`
- Every status transition, note, decision, and evidence upload automatically stamps the active analyst ID in the cryptographic ledger header `X-Analyst-ID`.

---

## 13. Uploading an Email (RFC-822 / .EML)
1. Open the Web Application at `http://localhost:5173/`.
2. Click **Start Investigation** (top-right blue button or center dashboard banner).
3. The **Investigation Workspace** opens.
4. Two ingestion methods are provided:
   - **Method A — File Drag & Drop:** Drag any `.eml` file into the upload zone (maximum 10 MB).
   - **Method B — Paste Raw RFC-822 Headers:** Paste full email headers including `Received:`, `Authentication-Results:`, `From:`, and `Subject:`.
5. Click **Analyze Message**.

---

## 14. Running an Investigation
When **Analyze Message** is clicked, the backend executes the deterministic forensic pipeline in under 1.5 seconds:
1. **Cryptographic Fingerprint:** Generates SHA-256 digest of raw payload.
2. **RFC-822 Transport Hop Traversal:** Parses all `Received` headers in reverse chronological order, identifying relay points, internal gateways, and the probable public origin IP.
3. **Cryptographic Authentication Check:** Extracts and validates `Received-SPF`, `DKIM-Signature`, and `DMARC` policies.
4. **Observable Extraction:** Isolates IP addresses, domains, Reply-To addresses, and URLs.
5. **Multi-Model Inference:** Runs Model 1 (Phishing), Model 2 (BEC), Model 3A (Identity Spoofing), Model 3B (Lookalike Domain), and Phase 12.5 (Disposable Email).
6. **Cross-Modal Signal Fusion:** Weighs signals, applies category caps, flags contradictions, and calculates explainable risk score.
7. **Attribution Assessment:** Applies non-attribution invariants and prescribes precise evidence gaps.
8. **Dossier & Ledger Creation:** Stores the case in Supabase and mints an evidence ledger entry.

---

## 15. Reading and Interpreting Results
The results screen displays the complete forensic assessment:
- **Threat Verdict & Score (0–100):**
  - `CRITICAL (85–100)` — Immediate active threat (Red).
  - `HIGH (70–84)` — Substantial malicious indicators (Orange).
  - `MEDIUM (40–69)` — Suspicious or conflicting signals (Amber).
  - `LOW (15–39)` — Low likelihood of threat (Green).
  - `INFORMATIONAL (0–14)` — Verified benign communication (Blue).
- **Primary Factors Breakdown:** Explains exactly which signals drove the score.
- **Authentication Matrix:** Visual badges for SPF, DKIM, and DMARC (`PASS`, `FAIL`, `NEUTRAL`, `NOT OBSERVED`).
- **Transport Route Visualizer:** Step-by-step relay hops showing public vs. private gateways.
- **Attribution Boundary Card:** Explicit non-attribution boundary declaration.

---

## 16. Cases & Investigation Management
Navigate to the **Cases** tab in the top navigation bar:
- Lists all active and historical forensic investigations.
- Shows Case ID (`CASE-XXXX`), Title, Threat Score, Priority, Status, and Creation Date.
- Filter cases by status: `all`, `new`, `open`, `under_review`, `escalated`, `resolved`, `closed`.
- Click on any case to enter its comprehensive forensic view.

---

## 17. Alerts Triage
Navigate to the **Alerts** tab:
- Dedicated triage console for high-risk inbound detections.
- Each alert highlights:
  - Subject line and spoofed entity.
  - Severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Source IP and sender domain.
  - **Quick Action:** Analysts can click **Triage Alert** or **Promote to Case** with one click.

---

## 18. Campaigns & Threat Actor Infrastructure
Navigate to the **Campaigns** tab:
- Groups individual attacks into coordinated threat clusters.
- **Campaign Relationship Graph:** Renders nodes connecting shared relay IPs, lookalike sender infrastructure, and shared crypto-wallet addresses.
- **Strict Anti-Generic Heuristics:** Generic cloud relays (Gmail, Microsoft 365, Amazon SES, Cloudflare) are excluded from clustering to prevent false campaign grouping.
- Displays campaign timeline, affected victim targets, and infrastructure footprint.

---

## 19. Threat Intelligence & External IOC Lookups
Navigate to the **Intelligence** tab:
- Dedicated IOC (Indicator of Compromise) search engine.
- Search any IP, domain, URL, or SHA-256 hash.
- Integrates live intelligence feeds:
  - **VirusTotal:** Detection ratios and malware categories.
  - **AbuseIPDB:** Abuse confidence score, total reports, and ISP ownership.
  - **GeoIP & ASN:** Autonomous System Number, organization, and country.
- **Fail-Safe Operational Rule:** If an external API is down or unconfigured, ANVESH displays `ENRICHMENT UNAVAILABLE` and **never** classifies an indicator as safe simply because external lookups failed.

---

## 20. Lookalike Domain Analysis (Model 3B)
- Evaluates domain structural anomalies designed to deceive human eyes.
- **Detection Capabilities:**
  - **Punycode / IDN Homoglyphs:** Detects Cyrillic, Greek, or Unicode character substitutions (e.g., `micrоsoft.com` using Cyrillic `о`).
  - **Levenshtein Distance:** Identifies typosquatting (e.g., `paypa1.com`, `amazn-support.com`).
  - **Subdomain Deception:** Identifies brand spoofing via prefixing (e.g., `login.microsoft.com.attacker-domain.org`).
  - **Random Forest Structural Classifier:** Weighs vowel-to-consonant ratios, token entropy, and hyphenation.

---

## 21. Identity Impersonation Detection (Model 3A)
- Evaluates header-level deception without relying on external threat feeds:
  - **Executive Display Name Spoofing:** Sender displays "Sundar Pichai" or "CEO Name" while sending from a generic public webmail (`@gmail.com`, `@yahoo.com`).
  - **Reply-To Interception:** Header `From` points to a legitimate corporate domain, but `Reply-To` diverts responses to an attacker-controlled address.
  - **Friendly-From Discrepancy:** Divergence between RFC-5322 `From` and RFC-5321 `Return-Path`.

---

## 22. Business Email Compromise (BEC) Analysis (Model 2)
- Evaluates payment diversion and social engineering urgency:
  - Urgent payroll or banking alteration requests.
  - Wire transfer rerouting and confidentiality demands.
  - Authority leverage ("Confidential directive from CEO, do not call to confirm").
  - Produces explainable linguistic feature breakdowns.

---

## 23. Disposable Email Intelligence (Phase 12.5)
- Evaluates sender addresses against an authoritative repository of **3,600+ disposable/burner domains** (e.g., `temp-mail.org`, `10minutemail`, `mailinator.com`).
- **Privacy Forwarder Distinction:** Distinguishes between illicit disposable burner addresses and legitimate privacy relays (e.g., Apple Private Relay, Mozilla Relay, SimpleLogin).
- Provides deterministic classification and the SHA-256 dataset hash for legal evidence.

---

## 24. Forensic Signal Fusion (Phase 9B)
The core analytical engine combining all independent signals:
- **Anti-Double-Counting Invariant:** Ensures that overlapping signals (e.g., text NLP risk + lookalike domain) do not compound uncontrollably beyond their logical contribution.
- **Category Caps:**
  - `Authentication & Transport`: Maximum 35 points.
  - `Content & Social Engineering`: Maximum 35 points.
  - `Identity & Lookalike`: Maximum 35 points.
  - `External Threat Intelligence`: Maximum 25 points.
- **Contradiction Detection:** Automatically flags discrepancies, such as `SPF PASS` coexisting with a high-confidence `BEC Payment Divert` attempt.

---

## 25. Attribution Assessment & Non-Attribution Invariant

> [!CAUTION]
> **Core Forensic Legal Invariant:** Transport headers, IP hops, and email addresses identify **originating infrastructure**, NOT human identity.

- Under no circumstances does ANVESH identify a human attacker name or nation-state sponsor from an email header alone.
- **Official Platform Declaration:**  
  `Actor Identity: NOT ESTABLISHED`
- In court testimony and incident briefings, the analyst must reiterate:
  > *"Email headers confirm infrastructure routing and authentication policy conformance; they do not establish physical actor identity without ISP subscriber logs, endpoint forensic correlation, or judicial subpoenas."*

---

## 26. Evidence Gaps & Prescriptive Guidance
For every investigation, ANVESH automatically identifies missing investigative links:
- *Need mailbox sign-in logs to evaluate account compromise.*
- *Need upstream MTA gateway message trace.*
- *Need DNS historical resolution records.*
- *Need banking institution verification for account alteration.*
This guides analysts on the precise evidence required to convert technical suspicion into legal proof.

---

## 27. Case Workflow State Machine
ANVESH enforces an auditable lifecycle state machine:
```text
[NEW] ──> [OPEN] ──> [UNDER_REVIEW] ──> [ESCALATED] ──> [RESOLVED] ──> [CLOSED]
```
- Only authorized analysts can advance case states.
- Reopening a closed case generates an audit record.
- Every state transition requires a documented operational reason.

---

## 28. Analyst Decision Management
- The **Analyst Decision** is kept strictly independent from the automated **System Risk Score**.
- An automated score of 88 (Critical) can be classified by an analyst as `FALSE_POSITIVE` if legitimate authorization is verified.
- Available decisions:
  - `CONFIRMED_THREAT`
  - `SUSPICIOUS_MONITORED`
  - `BENIGN_VERIFIED`
  - `FALSE_POSITIVE`
  - `INCONCLUSIVE_EVIDENCE`

---

## 29. Forensic Dossier Report Compilation
ANVESH compiles an exhaustive 16-section forensic dossier containing:
1. Dossier Header & Unique Case Identifier
2. Executive Summary & Verdict
3. Evidence Cryptographic Fingerprint (SHA-256)
4. Full RFC-822 Message Metadata
5. Transport Route & Received-Hop Ledger
6. Cryptographic Authentication Ledger (SPF, DKIM, DMARC)
7. Origin Infrastructure Analysis
8. Threat Intelligence Corroboration
9. Multi-Model Forensic Signal Breakdown
10. Campaign Association & Cluster Evidence
11. Multi-Modal Signal Fusion & Contradiction Log
12. Formal Attribution Boundary Statement
13. Prescriptive Evidence Gaps & Next Steps
14. Chain of Custody & Analyst Audit Trail
15. Forensic Limitations & Legal Disclaimers
16. Digital Verification Seal & Cryptographic Signature

---

## 30. PDF Export (Court-Ready Dossier)
- Endpoint: `GET /api/v1/cases/{case_id}/report/pdf`
- Generates a multi-page, court-ready PDF using ReportLab.
- Formatted with dark forensic styling, tables, SHA-256 verification seals, and pagination.
- Download directly from the Web UI: Click **Export Forensic Dossier (PDF)** in any case view.

---

## 31. Canonical JSON Export
- Endpoint: `GET /api/v1/cases/{case_id}/report/json`
- Exports the 100% equivalent structured data object for SIEM/SOAR ingestion (Splunk, Microsoft Sentinel, IBM QRadar).

---

## 32. Chain of Custody Ledger
Every case maintains an append-only custody ledger recording:
- Event Timestamp (UTC ISO-8601).
- Acting Analyst ID and Name.
- Action Performed (`INGESTION`, `STATUS_CHANGE`, `DECISION_RECORDED`, `REPORT_EXPORTED`).
- Payload Hash at time of action.

---

## 33. Evidence Cryptographic Integrity (SHA-256)
- The raw email content is hashed immediately upon ingestion: `hashlib.sha256(raw_bytes).hexdigest()`.
- The hash is permanently embedded in the case record and verification seal.
- If even one byte of the raw email is modified, the hash verification fails instantly.

---

## 34. The 8 SIH Demo Scenarios

All scenario fixtures are located in `backend/tests/fixtures/sih_demo/`.

| Scenario | Fixture File | What It Demonstrates | Expected Score & Key Signal |
| :--- | :--- | :--- | :--- |
| **01 Classic Phishing** | `scenario_01_classic_phishing.eml` | Credential harvesting with urgent suspension language | `CRITICAL (85+)` • High NLP phish probability |
| **02 BEC Payment Change** | `scenario_02_bec_payment_change.eml` | Executive wire reroute to fraudulent bank account | `HIGH (70+)` • Urgent financial alteration |
| **03 Lookalike Domain** | `scenario_03_lookalike_impersonation.eml` | Typosquatted / homoglyph brand impersonation | `HIGH (70+)` • Model 3B structural anomaly |
| **04 Authenticated BEC** | `scenario_04_authenticated_bec.eml` | Forensic Gap: `SPF/DKIM/DMARC PASS` but fraudulent Reply-To | `HIGH (70+)` • Behavioral risk despite Auth PASS |
| **05 Campaign Tracking** | `scenario_05a_campaign_email_1.eml`<br>`scenario_05b_campaign_email_2.eml` | Two distinct emails sharing origin relay IP & infrastructure | Correlated under single Campaign ID |
| **06 Benign Legitimate** | `scenario_06_benign_legitimate.eml` | True negative verification with all legitimate headers | `LOW (<20)` • Clean verification |
| **07 Disposable Email** | `scenario_07_disposable_email.eml` | Ephemeral burner provider address detection | `SUSPICIOUS` • Flagged disposable domain |
| **08 Attribution Dead-End** | `scenario_08_attribution_deadend.eml` | Anonymized multi-relay path proving non-attribution | `Actor Identity: NOT ESTABLISHED` |

---

## 35. Mobile Application Workflow
1. Open the ANVESH mobile application on Android/iOS.
2. **Home Screen:** Live telemetry, quick status, and health indicators.
3. **Cases Tab:** View all active investigations synchronized with the desktop workspace.
4. **Case Detail Screen:**
   - Review *Why Flagged* forensic reasoning.
   - Inspect transport route and authentication badges.
   - View Attribution Boundary statement.
   - Execute report generation and status progression on the go.

---

## 36. Android APK Generation & Deployment

### Step 1: Verify TypeScript:
```powershell
cd "c:\Users\Rishabh Bansal\OneDrive\Desktop\Razorpay Buildathon\SIH2026\mobile"
npx tsc --noEmit
```

### Step 2: Build Internal APK with EAS:
```powershell
eas build --platform android --profile preview
```
- EAS uploads assets and executes a remote cloud build producing a standalone `.apk`.
- The build terminal outputs a direct download link and QR code upon completion.

### Step 3: Install on Device:
- **Method A:** Scan the terminal QR code with your Android phone and tap **Install**.
- **Method B:** If connected via USB with Developer Mode:
  ```powershell
  adb install anvesh-preview.apk
  ```

---

## 37. Operator Troubleshooting Guide

| Problem | Cause | Diagnostic Command | Solution |
| :--- | :--- | :--- | :--- |
| **Backend fails on start** | Port 8000 in use | `Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess` | Terminate conflicting process or kill existing uvicorn |
| **Web UI shows "API Offline"** | Backend not running | `curl http://localhost:8000/api/v1/health` | Start backend in Terminal 1 |
| **Mobile shows Network Error** | Phone using `localhost` | Inspect `mobile/.env` | Change API URL to PC LAN IPv4 (e.g., `192.168.1.5:8000`) |
| **CORS Error in Browser Console** | Origin not in allowed list | Check `backend/app/core/config.py` | Ensure client port is in `CORS_ORIGINS` |
| **Supabase Status Red** | Network disconnected | `supabase.ping()` | Re-check internet connection; SQLite fallback remains active |
| **Windows Firewall blocks phone** | Inbound rule missing | `Test-NetConnection -ComputerName 192.168.1.5 -Port 8000` | Add firewall rule for port 8000 |

---

## 38. Clean Shutdown Procedure
To shut down the entire ANVESH platform safely:
1. **Web Frontend:** In Terminal 2, press `CTRL + C` and type `y`.
2. **Mobile Server:** In Terminal 3, press `CTRL + C`.
3. **Backend Engine:** In Terminal 1, press `CTRL + C`. Uvicorn will execute a graceful shutdown.

---

## 39. Demo Reset Procedure
To return the workspace to a clean state for a new demonstration:
1. Restart the FastAPI backend.
2. In SQLite mode: Delete `backend/anvesh_dev.db` if you wish to wipe local session data; the backend will automatically recreate empty tables on the next startup.
3. In Supabase mode: New cases receive clean unique IDs (`CASE-XXXX`) so historical test runs do not conflict with live demonstrations.

---

## 40. Final SIH Demo Operator Checklist

- [ ] Python 3.12 verified (`python --version`).
- [ ] Node.js v22 verified (`node --version`).
- [ ] Backend running on `http://localhost:8000` (Health check returns `200 OK`).
- [ ] Web application accessible at `http://localhost:5173/`.
- [ ] Header brand displays official transparent ANVESH mark without box borders.
- [ ] All 9 demo EML fixtures present in `backend/tests/fixtures/sih_demo/`.
- [ ] PC LAN IPv4 verified for mobile companion.
- [ ] Scenario 01 uploaded and verified (Critical Phishing score rendered).
- [ ] Scenario 04 uploaded and verified (Authenticated BEC with non-attribution boundary).
- [ ] Scenario 05 uploaded and verified (Campaign clustering demonstrated).
- [ ] PDF dossier export downloaded and verified.
- [ ] Complete automated test suite verified (223/223 tests passing).
