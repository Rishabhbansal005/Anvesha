# ANVESH — End-to-End Objective Validation Checklist
**Platform:** ANVESH Forensic Intelligence (SIH26106) | **Version:** `2.0.0-workspace`

---

## 1. Infrastructure & Environment
- [ ] **Python Version Verification:** Run `python --version` → returns Python 3.12.x.
- [ ] **Node.js Version Verification:** Run `node --version` → returns Node.js v20.x or v22.x.
- [ ] **EAS CLI Verification:** Run `eas --version` → returns `eas-cli/23.x.x`.
- [ ] **Database Connection:** Run `python -c "from app.database.supabase_client import supabase; print(supabase.ping())"` → returns `True`.
- [ ] **Port Availability:** Port 8000 (Backend) and Port 5173 (Web) free and unblocked.

---

## 2. Backend Engine (FastAPI)
- [ ] **Backend Startup:** Execute `uvicorn app.main:app --port 8000` → boots without unhandled exceptions.
- [ ] **Health Endpoint:** Query `GET /api/v1/health` → returns HTTP 200 with status `HEALTHY` and `supabase_connected: true`.
- [ ] **Interactive API Docs:** Navigate to `http://localhost:8000/docs` → Swagger UI renders all 8 tag routers.
- [ ] **Payload Size Enforcement:** Submit file >10 MB to `/api/v1/emails/analyze` → returns HTTP 413 Payload Too Large.
- [ ] **Automated Test Regression:** Run `pytest tests -q` in `backend/` → passes 223/223 tests.

---

## 3. Web Dashboard (React 19 + Vite)
- [ ] **Web Build Pass:** Run `npm run build` in `web/` → exits with code 0 (`tsc -b && vite build`).
- [ ] **Dev Server Execution:** Run `npm run dev` in `web/` → Vite server starts on `http://localhost:5173/`.
- [ ] **Header Brand Rendering:** Top-left header renders official transparent ANVESH mark with zero dark rectangle artifacting.
- [ ] **Language Consistency:** Header contains no extraneous text; focuses strictly on brand mark and navigation tabs.
- [ ] **Telemetry Status Pill:** Header indicates live platform connectivity with green `• SUPABASE LIVE` indicator.

---

## 4. Email Ingestion & Transport Parsing
- [ ] **File Drag & Drop:** Dragging `.eml` into workspace renders file name, size, and triggers parse pipeline.
- [ ] **Raw Header Ingestion:** Pasting RFC-822 header block into text area executes cleanly.
- [ ] **SHA-256 Fingerprint:** System computes verifiable SHA-256 digest of submitted email body and headers.
- [ ] **Received Hop Traversal:** Ingestion isolates all intermediate MTA nodes in chronological reverse order.
- [ ] **Public Origin IP Identification:** System identifies earliest routable public IP and suppresses private LAN hops.

---

## 5. Cryptographic Authentication
- [ ] **SPF Verification:** System parses `Received-SPF` / `Authentication-Results` to detect `PASS`, `FAIL`, or `NEUTRAL`.
- [ ] **DKIM Signature Analysis:** Identifies cryptographic domain signature validation status.
- [ ] **DMARC Policy Conformance:** Evaluates alignment against published domain sender policies.
- [ ] **Visual Authentication Matrix:** Web and mobile dashboards display distinct visual badges for all three protocols.

---

## 6. Multi-Model Threat Classification
- [ ] **Model 1 (Phishing NLP):** Detects credential harvesting linguistic patterns and returns probability score.
- [ ] **Model 2 (BEC Fraud):** Detects wire diversion, urgency cues, and payroll alteration behavior.
- [ ] **Model 3A (Identity Spoofing):** Detects executive display-name spoofing and Reply-To mismatch.
- [ ] **Model 3B (Lookalike Domain):** Identifies Punycode, homoglyphs, and typosquatted sender domains.
- [ ] **Model Frozen Hashes:** Model artifacts match baseline SHA-256 cryptographic hashes exactly.

---

## 7. Disposable & Temporary Email Intelligence (Phase 12.5)
- [ ] **Disposable Domain Lookup:** Flag addresses from burner providers (e.g., `temp-mail.org`).
- [ ] **Privacy Forwarder Distinction:** Distinguishes between burner domains and legitimate relays (Apple, Mozilla).
- [ ] **Dataset Verification:** Dataset includes verifiable SHA-256 fingerprint for forensic admissibility.

---

## 8. Forensic Signal Fusion & Risk Scoring (Phase 9B)
- [ ] **Anti-Double-Counting:** Overlapping NLP and behavioral signals do not inflate scores past category caps.
- [ ] **Category Weighting:** Risk components respect mathematical limits (Auth: 35, Content: 35, Identity: 35, Intel: 25).
- [ ] **Contradiction Detection:** System explicitly flags discrepancies (e.g., `SPF PASS` with fraudulent `Reply-To`).
- [ ] **Explainable Verdict:** Results breakdown highlights top driving factors behind the calculated threat level.

---

## 9. Campaign Correlation & Threat Clustering
- [ ] **Multi-Message Correlation:** Emails sharing non-generic relay infrastructure are clustered into a Campaign.
- [ ] **Anti-Generic Exclusion:** Cloud infrastructure (AWS, Microsoft 365, Gmail) is excluded from false clustering.
- [ ] **Campaign Relationship Graph:** Renders nodes connecting shared IPs, sender domains, and affected targets.
- [ ] **Temporal Timeline:** Chronological timeline displays attack progression over time.

---

## 10. Case Workflow & State Machine (Phase 11)
- [ ] **Case Ingestion:** New investigation automatically mints case record with unique `CASE-XXXX` identifier.
- [ ] **State Transitions:** Case transitions through `NEW` → `OPEN` → `UNDER_REVIEW` → `ESCALATED` → `RESOLVED`.
- [ ] **Analyst Independence:** Analyst Decision (`CONFIRMED_THREAT`, `FALSE_POSITIVE`, etc.) is recorded separately from System Risk.
- [ ] **Audit Logging:** Every state change, note, and assignment records timestamp and analyst ID.

---

## 11. Attribution Assessment & Non-Attribution Invariant
- [ ] **Legal Invariant:** Platform displays `Actor Identity: NOT ESTABLISHED` across all screens.
- [ ] **Infrastructure Distinction:** Displays `Probable Origin Infrastructure`, never "Attacker Location".
- [ ] **Evidence Gaps Generation:** Recommends missing investigative data (e.g., mailbox sign-in logs, message trace).

---

## 12. Forensic Report Export & Custody (Phase 10)
- [ ] **Signed PDF Generation:** Query `GET /api/v1/cases/{case_id}/report/pdf` → downloads valid PDF document.
- [ ] **ReportLab Formatting:** PDF includes dark forensic theme, tables, verification seal, and pagination.
- [ ] **Canonical JSON Parity:** Query `GET /api/v1/cases/{case_id}/report/json` → matches PDF data with 100% parity.
- [ ] **Chain of Custody Section:** Report lists tamper-evident event log with analyst signatures and hashes.

---

## 13. Mobile Companion Application (Expo SDK 52)
- [ ] **TypeScript Check:** Run `npx tsc --noEmit` in `mobile/` → exits with code 0.
- [ ] **Expo Server Launch:** Run `npx expo start` in `mobile/` → dev server boots with valid QR code.
- [ ] **Real Device Connectivity:** Mobile connects to PC LAN IP (`http://192.168.1.5:8000/api/v1`) without timeout.
- [ ] **Mobile Screens Validation:** Home, Cases, Case Detail, and Alerts render cleanly with native navigation.
- [ ] **Mobile Brand Mark:** Displays official square app icon in header and launcher.

---

## 14. Android APK Deployment
- [ ] **EAS Configuration Check:** `mobile/eas.json` contains `"preview"` profile with `buildType: "apk"`.
- [ ] **Build Command Validation:** `eas build --platform android --profile preview` initiates cloud APK pipeline.
- [ ] **Standalone Installation:** APK installs cleanly on physical Android phone via QR download or ADB.
- [ ] **Crash-Free Execution:** App runs smoothly on physical device without crashing or white-screening.

---

## 15. The 8 SIH Demo Scenarios
- [ ] **Scenario 01 (Classic Phishing):** Score `85+ (CRITICAL)` • High NLP Phishing.
- [ ] **Scenario 02 (BEC Payment Fraud):** Score `70+ (HIGH)` • Financial reroute detected.
- [ ] **Scenario 03 (Lookalike Domain):** Score `70+ (HIGH)` • Model 3B homoglyph detected.
- [ ] **Scenario 04 (Authenticated BEC):** `SPF/DKIM/DMARC PASS` + high behavioral risk + non-attribution boundary.
- [ ] **Scenario 05 (Campaign Tracking):** Emails 5a & 5b correlate under shared Campaign ID.
- [ ] **Scenario 06 (Benign Legitimate):** Score `<20 (LOW)` • Zero false positives.
- [ ] **Scenario 07 (Disposable Email):** Classified as `DISPOSABLE` burner domain.
- [ ] **Scenario 08 (Attribution Dead-End):** Multi-hop anonymized proxy; confirms `NOT ESTABLISHED`.
