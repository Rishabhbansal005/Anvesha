# ANVESH Phase 5 — Product Intelligence & Investigation UX Integration

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Phase:** Phase 5 (Product Intelligence & Investigation UX Integration)  
**Governance State:** Phase 4 ML Models & Evaluation Artifacts **FROZEN & UNMODIFIED**

---

## 1. Executive Summary

Phase 5 transitions ANVESH from isolated ML benchmarking into a unified, analyst-grade, end-to-end cyber forensic investigation experience. 

### Core Product Distinction
> **ANVESH is NOT:** `"Upload email → AI says phishing."`  
> **ANVESH IS:** `"Upload email → reconstruct evidence → correlate intelligence → assess risk → explain findings → establish attribution boundary → recommend next investigation step."`

Every visible metric, indicator, and risk score in the platform is derived from authentic email parsing, cryptographic verification, relay hop extraction, threat intelligence correlations, and statistical language modeling. No simulated or fabricated values are displayed.

---

## 2. Capabilities Reused & Integrated

| Capability / Engine | Phase Origin | Integration Status in Phase 5 |
| :--- | :--- | :--- |
| **Model 1 Text Classifier** | Phase 4 | Integrated strictly as `TEXT / LANGUAGE SIGNAL (MODEL 1)` with subject/body n-gram indicator attribution. Explicitly labelled uncalibrated and non-authoritative on identity. |
| **Authentication Engine** | Phase 2 | Full SPF, DKIM, and DMARC verification with explicit analyst notice: *"Authentication PASS does not prove sender account is trustworthy (Compromised Account / BEC)"*. |
| **Received-Chain Relay Engine** | Phase 2 | Chronological relay hops with hop categorization (Preserved, Inferred, Unavailable) and forensic boundary delineation. |
| **Geographic & ASN Intelligence** | Phase 3 | Geolocation labelled as *"Approximate IP-associated location"* with ISP, ASN, network type, and IP confidence metadata. |
| **Threat Intelligence Aggregation** | Phase 3 | Live multi-feed indicators (VirusTotal, AbuseIPDB, Tor, VPN, Proxy) with source provenance and transparent *"Unavailable"* fallbacks. |
| **Combined Risk Scoring Engine** | Phase 2/3 | Multi-category weighted breakdown across 4 distinct dimensions: Text Signal (/30), Forensic Auth (/25), Infrastructure (/25), and BEC Indicators (/20). |
| **Attribution Boundary Engine** | Phase 2 | Rigid forensic boundary declaring `Actor Identity: NOT ESTABLISHED` unless cryptographic/session evidence establishes person-level identity. |
| **Evidence Gap Engine** | Phase 2 | Explicit structural breakdown of *What We Know*, *What We Cannot Establish*, and *Prescribed Next Telemetry Steps*. |
| **Case Management & Dossier Export** | Phase 2 | End-to-end evidence logging, status tracking, forensic timeline, SHA-256 evidence hashing, and 21-layer dossier generation. |

---

## 3. Architecture & User Experience Enhancements

### 3.1 6-Point Top Forensic Summary Bar
Located immediately above the 3-pane investigation workspace, delivering instant forensic orientation:
1. **Threat Risk:** Visual severity chip & normalized score (`82/100 · HIGH`).
2. **Origin Confidence:** Confidence rating based on observed public infrastructure hops (`MEDIUM` / `HIGH`).
3. **Authentication Matrix:** Concatenated status chips (`SPF PASS · DKIM PASS · DMARC PASS`).
4. **Probable Origin IP:** Monospace display of the earliest observed public relay node.
5. **Observed Infrastructure:** Network classification chip (`TOR EXIT NODE` / `DATACENTER / HOSTING`).
6. **Forensic Actor Identity:** Prominently locked to `NOT ESTABLISHED` to prevent confirmation bias.

### 3.2 Model 1 Presentation (Text / Language Signal)
- **Positioning:** Presented as a statistical NLP signal examining textual features (urgency, remittance terms, credential pressure), rather than an authoritative verdict.
- **Transparency Notice:** Added explainer stating: *"Model 1 evaluates email subject/body language only. It is one evidence source within the ANVESH forensic assessment. Raw logistic sigmoid probability is uncalibrated."*
- **Probability:** Clearly displays probability without claiming posterior calibration.

### 3.3 Combined Risk Assessment Breakdown
The primary risk score is presented alongside a 4-bar contribution decomposition:
- **ML / Text Signal:** Max 30 pts (Weight: 0.30)
- **Forensic / Authentication:** Max 25 pts (Weight: 0.25)
- **Infrastructure Intelligence:** Max 25 pts (Weight: 0.25)
- **BEC / Behavioral Indicators:** Max 20 pts (Weight: 0.20)

### 3.4 Forensic Attribution Boundary & Evidence Gap Engine
Clearly segregates verified forensic facts from evidentiary unknowns:
- **What We Know (Preserved):** Email RFC-5322 headers, cryptographic SPF/DKIM/DMARC signatures, relay hop chain, passive DNS/RDAP records, multi-engine threat reputation.
- **What We Cannot Establish:** Mailbox sign-in activity, tenant-level message traces, mailbox forwarding/inbox rules, sender endpoint compromise status.
- **Recommended Analyst Action:** Prescribes actionable secondary pivots (e.g., query Microsoft 365 Purview audit logs for anomalous OAuth grant tokens or IP sign-in spikes).

### 3.5 Comprehensive Forensic Dossier Export
Generates an analyst-ready, 21-layer forensic dossier containing:
- Cryptographic SHA-256 evidence integrity hash
- Complete message RFC-822 metadata & header trace
- Authentication verification results with alignment status
- Chronological relay timeline with IP/ASN geolocation
- Multi-source threat intelligence report
- Model 1 text signal score and extracted n-gram tokens
- Behavioral BEC and financial manipulation markers
- Formal Attribution Boundary statement and missing evidence gaps
- Chain-of-custody timestamps and investigator sign-off

---

## 4. API & Backend Implementation

### `POST /api/v1/emails/analyze`
Enhanced response payload structure:
- Added `category_scores`: Granular breakdown of risk contributions across `ml_risk`, `forensic_auth_risk`, `infrastructure_risk`, and `behavior_bec_risk`.
- Added `ml_signal`: Structured object containing `prediction`, `probability`, `is_threat`, `confidence`, and `key_indicators`.

### `GET /api/v1/cases/{case_id}` & `GET /api/v1/cases/{case_id}/report`
Enhanced to provide complete forensic reconstruction:
- Bundles full `ml_signal`, `category_scores`, `infrastructure`, `attribution`, and `evidence_gaps` into case records and downloadable forensic dossiers.

---

## 5. Mobile Status

- **Status:** Mobile application files (`mobile/src/screens/CasesScreen.tsx`, `AlertsScreen.tsx`, `QuickLookupScreen.tsx`) were audited and typechecked (`npx tsc --noEmit` passed with 0 errors).
- **Architecture:** Operates as an **Incident Response & Decision Companion** (*"Web investigates the evidence. Mobile operationalizes the investigation."*).
- **Scope:** Existing mobile components already enforce `Actor Identity: NOT ESTABLISHED`, Origin Confidence, and Action Recommendations; no new mobile code changes were introduced during Phase 5.

---

## 6. Error & Edge Case Handling

The pipeline handles diverse forensic edge cases without crashes or fabricated conclusions:
1. **Malformed `.eml` / Missing Headers:** Gracefully captures raw text, computes SHA-256, flags header truncation, and marks affected layers as `Unavailable`.
2. **Private IP-Only Relays:** Identifies RFC-1918 internal relays (e.g., `10.0.0.0/8`, `192.168.0.0/16`), notes them as internal hops, and classifies Origin Infrastructure as `Internal Network / Private Infrastructure`.
3. **Compromised Account (SPF/DKIM PASS with Phishing Content):** Correctly flags the authentication as `PASS`, but increases risk score via text signal + BEC markers, accompanied by a high-priority evidence gap warning.
4. **Cloud / SaaS Relays (M365, Google Workspace, SendGrid):** Recognizes legitimate enterprise infrastructure, avoiding false IP reputation flags while evaluating underlying envelope anomalies.
5. **External TI Outages / Timeouts:** If VirusTotal, AbuseIPDB, or RDAP APIs are unreachable or unconfigured, the UI cleanly renders `Unavailable` rather than falsely asserting `Clean`.

---

## 7. Verification & Test Results

### 7.1 Backend Test Suite
Executed the full pytest test suite against the updated FastAPI application:
```
============================= test session starts =============================
platform win32 -- Python 3.12.3, pytest-8.2.0, pluggy-1.6.0
rootdir: C:\Users\Rishabh Bansal\OneDrive\Desktop\SIH2026\backend
collected 21 items

tests\test_email_pipeline.py ...                                         [ 14%]
tests\test_enrichment_attribution.py ..............                      [ 80%]
tests\test_ml_pipeline.py ....                                           [100%]
====================== 21 passed, 33 warnings in 27.85s =======================
```
**Result:** 21/21 tests PASSED (100% success rate).

### 7.2 Frontend Production Build & TypeScript Check
Executed full Vite + TypeScript compilation on `web`:
```
> tsc -b && vite build
vite v8.2.2 building client environment for production...
transforming...
✓ 1838 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   0.69 kB │ gzip:  0.44 kB
dist/assets/index-Bi84u6Rc.css   30.85 kB │ gzip:  6.61 kB
dist/assets/index-QYgeJMNt.js   306.36 kB │ gzip: 83.95 kB
✓ built in 4.51s
```
**Result:** 0 TypeScript errors, 0 build warnings.

### 7.3 Mobile Typecheck
Executed TypeScript static verification on `mobile`:
```
npx tsc --noEmit
Exit code: 0
```
**Result:** 0 TypeScript errors.

---

## 8. Files Modified in Phase 5

| File Path | Description of Changes |
| :--- | :--- |
| `backend/app/api/v1/endpoints/emails.py` | Added `category_scores` and `ml_signal` payload structure to email analysis endpoint. |
| `backend/app/api/v1/endpoints/cases.py` | Updated case details and report generation endpoints with full forensic metadata and evidence gaps. |
| `web/src/types/index.ts` | Added TypeScript interfaces for `CategoryScores`, `CategoryScoreItem`, and `MLSignalData`. |
| `web/src/pages/InvestigationWorkspace.tsx` | Implemented 6-point top forensic summary bar, Model 1 text signal panel, 4-bar risk contribution breakdown with strict 0 fallbacks, authentication warning matrix, and 21-layer forensic dossier modal. |
| `ml/evaluation/PHASE5_PRODUCT_INTEGRATION.md` | Authoritative Phase 5 documentation, verification, and audit record. |

---

## 9. Phase 5 Final Audit

- **Mobile Implementation Status:** Verified. Mobile code was audited and typechecked (0 errors), but not modified in Phase 5.
- **Example IP Verification:** Verified. No fake forensic IPs (`185.220.101.5` / `185.220.101.42`) exist in production UI or backend logic. All IPs are dynamically extracted from email headers.
- **Dynamic Data-Flow Verification:** Verified. All 16 UI fields (Threat Risk, Origin Confidence, Authentication, Infrastructure, Actor Identity, Model 1 Signal, etc.) strictly bind to backend analysis payloads.
- **Attribution Wording Verification:** Verified. Clean of "Attacker IP/Location/Identity" or "Hacker" terminology; strictly employs forensic phrasing (`Probable Origin Infrastructure`, `Approximate IP-associated location`, `Actor Identity: NOT ESTABLISHED`).
- **Model 1 Wording Verification:** Verified. Clearly presented as a text/language signal with explicit uncalibrated probability notice.
- **Risk Score Verification:** Verified. Category score breakdown matches backend bounds (Text `/30`, Auth `/25`, Infra `/25`, BEC `/20`).
- **Final Test Results:** Backend 21/21 passed; Web build 0 errors; Mobile typecheck 0 errors.

---

## 10. Governance Confirmation — Phase 4 Frozen Artifact Integrity

All Phase 4 machine learning models, hyperparameters, thresholds, datasets, and benchmark evaluation outputs remain **FROZEN, UNMODIFIED, AND UNTOUCHED**.

| Frozen Artifact | Status | SHA-256 Hash Verified |
| :--- | :--- | :--- |
| `ml/models/phishing_baseline_v1/model.joblib` | **FROZEN** | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` |
| `ml/models/phishing_baseline_v1/metadata.json` | **FROZEN** | `39a9b88a813cb3fc80eba27a808933ccc0c3923625ffeed588004eeb957cdd83` |
| `ml/models/phishing_baseline_v1/top_features.json` | **FROZEN** | `5a811278614f9d08f842aca8145ca4cf41292574d5e9c37b6bfbf0c392e38fa2` |
| `ml/datasets/processed/independent_test_iwspa.jsonl` | **FROZEN** | `a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552` |
| `ml/datasets/challenge/anvesh_challenge_50.jsonl` | **FROZEN** | `a5abe63187a59eb32c730ec2dd0f7d248629fd7a50679baaa296bd224092c68f` |
| `ml/evaluation/PHASE4_FINAL_MODEL_SUMMARY.md` | **FROZEN** | `ca91f82029b6572106888aa8850e347b6817e8cb0227600d4e4e1e86f14079e2` |

**Final Statement:**
> **"Phase 4 ML/evaluation artifacts remain frozen and unchanged."**
