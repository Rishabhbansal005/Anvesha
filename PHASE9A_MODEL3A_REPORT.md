# ANVESH — PHASE 9A COMPLETION REPORT: MODEL 3A (IDENTITY & HEADER IMPERSONATION DETECTION)

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Capability:** Model 3A (Identity & Header Impersonation Detection Engine)  
**Phase:** Phase 9A  
**Implementation Mode:** Governed Deterministic Baseline (`model3a_deterministic_v1`)  
**Attribution Boundary:** Actor Identity: NOT ESTABLISHED

---

## 1. Executive Summary & Objective

In Phase 9A, ANVESH expanded its defense-in-depth detection suite with **Model 3A**, focusing on suspicious email identity and header relationships. 

While **Model 3B** handles lookalike and typosquatted domain detection at the infrastructure layer, **Model 3A** evaluates identity discrepancies and transport header manipulation:
- Executive display-name impersonation and authority impersonation
- Supplier/vendor identity impersonation
- Sender address vs. display-name mismatch
- Reply-To identity mismatch
- Header identity inconsistencies
- Known/trusted identity vs. observed sender mismatch
- Combined evidence integration with Model 3B (lookalike domain support)

### Mandatory Governance Guarantees Enforced:
1. **Evidence & Correlation Only:** Model 3A establishes technical and lexical evidence of impersonation. It **NEVER** claims a real person committed the attack, identifies an attacker, or converts an impersonation signal into actor attribution.
2. **Mandatory Attribution Language:**
   - `"Identity Impersonation Signal"`
   - `"Observed Sender"`
   - `"Observed Identity"`
   - `"Actor Identity: NOT ESTABLISHED"`
3. **No Fabricated Machine Learning Benchmarks:** Because no public corpus provides verified ground truth for RFC-822 executive impersonation and trusted identity relationships, ML training was formally blocked. Model 3A is implemented as an explainable, deterministic baseline engine.
4. **Authentication Invariant:** Cryptographic authentication PASS (`SPF: PASS`, `DKIM: PASS`, `DMARC: PASS`) does **not** erase or suppress identity impersonation indicators (protecting against compromised accounts).

---

## 2. Architecture Inspection

Before writing code, ANVESH's complete architecture was audited:
- **Backend Email Ingestion (`backend/app/api/v1/endpoints/emails.py`):** Ingestion parses raw RFC-822 headers using standard library `email.message_from_string` and extracts `From`, `To`, `Subject`, `Reply-To`, `Return-Path`, `Message-ID`, `Authentication-Results`, and `Received` chains.
- **Risk Engine (`backend/app/services/risk_engine.py`):** Consolidated explainable scoring engine. Incorporates `ml_risk` (0–30), `forensic_auth_risk` (0–25), `infrastructure_risk` (0–25), `behavior_bec_risk` (0–20), and `lookalike_impersonation_risk` (0–15).
- **Model Freezes:** Models 1, 2, and 3B remained completely untouched with verified SHA-256 integrity.

---

## 3. Dataset Investigation & Governance Decision

As documented in [`ml/datasets/model3a/MODEL3A_DATASET_AUDIT.md`](file:///c:/Users/Rishabh%20Bansal/OneDrive/Desktop/Razorpay%20Buildathon/SIH2026/ml/datasets/model3a/MODEL3A_DATASET_AUDIT.md), candidate datasets were audited:
- **Enron Email Corpus:** ~500k messages, real RFC-822 headers, but 100% benign internal communications with zero labeled spoofing or attack ground truth.
- **Jose Nazario Phishing Corpus:** ~4,500 messages, binary phish/ham labels only; lacks fine-grained executive identity pairs or trusted corporate directory mappings.
- **IWSPA AP 2018:** Sanitized/redacted headers; destroys identity relationship signals.
- **SpamAssassin Public Corpus:** Outdated spam/ham; lacks BEC or executive fraud labels.
- **Zenodo BEC Collections:** Body-only text; strips RFC-822 transport headers entirely.

### Governance Decision:
> **"Model 3A is implemented as a governed deterministic baseline because no sufficiently verified public identity-impersonation ground-truth corpus was established."**

---

## 4. Model 3A Baseline Design & Signals

Model 3A is implemented in [`ml/inference/identity_impersonation_predictor.py`](file:///c:/Users/Rishabh%20Bansal/OneDrive/Desktop/Razorpay%20Buildathon/SIH2026/ml/inference/identity_impersonation_predictor.py) and evaluated in [`ml/evaluation/MODEL3A_BASELINE_EVALUATION.md`](file:///c:/Users/Rishabh%20Bansal/OneDrive/Desktop/Razorpay%20Buildathon/SIH2026/ml/evaluation/MODEL3A_BASELINE_EVALUATION.md).

### 7 Deterministic Signals & Weights:
1. **SIGNAL 1 (`DISPLAY_NAME_DOMAIN_MISMATCH`, +30 pts):** Observed display name matches a registered trusted identity (e.g. executive or key supplier), but observed sender domain differs from the trusted corporate domain.
2. **SIGNAL 2 (`EXECUTIVE_EXTERNAL_DOMAIN`, +25 pts):** Display name contains executive authority indicators ("CEO", "CFO", "Director", "President", etc.) or matches leadership identity, but originates from public freemail (`gmail.com`, `yahoo.com`, `protonmail.com`, etc.) or external consumer infrastructure.
3. **SIGNAL 3 (`SUSPICIOUS_SENDER_DOMAIN_RELATION`, +15 pts):** Personal display name paired with generic operational sender local-part (`billing`, `payments`, `wire`, `accounts`) on an external domain.
4. **SIGNAL 4 (`REPLY_TO_MISMATCH`, +25 pts):** The RFC-822 `Reply-To` address differs from the observed `From` sender address. Indicator of route manipulation or reply diversion.
5. **SIGNAL 5 (`DISPLAY_NAME_TRUSTED_DOMAIN_MISMATCH`, +15 pts):** Display name references trusted organization domain while sender domain is an unrelated third-party.
6. **SIGNAL 6 (`MODEL3B_LOOKALIKE_SUPPORT`, +15 pts):** Corroboration from Model 3B when the sender domain is identified as a lookalike/typosquat of the target brand.
7. **SIGNAL 7 (`AUTH_FAILURE_CONTEXT`, +10 pts):** Cryptographic authentication failure (`SPF: FAIL`, `DKIM: FAIL`, or `DMARC: FAIL`), elevating transport spoofing risk.

### Scoring:
- Score Range: **0–100** (`identity_impersonation_score = min(100, sum(points))`).
- Threshold: $\ge 40$ flags `identity_impersonation_detected = True`.
- Confidence: $\ge 70$ `HIGH`, $40–69$ `MEDIUM`, $1–39$ `LOW`, $0$ `NONE`.
- Never labeled as probability.

---

## 5. Backend & Risk Engine Integration

1. **Pydantic Schemas:** Created [`backend/app/schemas/identity.py`](file:///c:/Users/Rishabh%20Bansal/OneDrive/Desktop/Razorpay%20Buildathon/SIH2026/backend/app/schemas/identity.py).
2. **Service Integration:** Created [`backend/app/services/identity_impersonation_service.py`](file:///c:/Users/Rishabh%20Bansal/OneDrive/Desktop/Razorpay%20Buildathon/SIH2026/backend/app/services/identity_impersonation_service.py) with clean test fixture registry.
3. **Risk Engine Extension:** Updated `calculate_risk` in [`backend/app/services/risk_engine.py`](file:///c:/Users/Rishabh%20Bansal/OneDrive/Desktop/Razorpay%20Buildathon/SIH2026/backend/app/services/risk_engine.py) to accept `identity_risk: int = 0` (0–15 points), scaling explainably from the 0–100 score.
4. **FastAPI Endpoints:**
   - Exposed dedicated endpoint `POST /api/v1/emails/identity-impersonation-detect`.
   - Integrated into `POST /api/v1/emails/analyze` pipeline.
   - Integrated into `GET /api/v1/cases/{case_id}` detail endpoint.

---

## 6. Web & Mobile UI Integration

### Web Desktop Investigation Workspace:
- Added `Identity Impersonation (M3A)` tab and button to workspace navigation.
- Added `Identity Impersonation` score bar to the Overview risk breakdown (`+{score} / 15`).
- Added dedicated `IDENTITY IMPERSONATION (MODEL 3A)` card in Overview and dedicated tab view:
  - Severity badge (`HIGH`, `MEDIUM`, `LOW`, `NONE`)
  - Score meter: `{score} / 100`
  - Observed Identity & Observed Sender
  - Trusted Identity Context
  - Evaluated Impersonation Signals list with points breakdown
  - Authentication status pills with compromised-mailbox disclaimer: *"Authentication passed, but identity impersonation indicators remain."*
  - Attribution Boundary: `Actor Identity: NOT ESTABLISHED`.

### Mobile Incident Response Companion:
- Added compact `IDENTITY IMPERSONATION` card to `CaseDetailScreen.tsx` displayed when impersonation signals exist.
- Shows severity badge, score, observed identity, observed sender, Reply-To mismatch, top 2–3 signals, and attribution boundary banner.
- Fully compliant with 44pt touch targets and accessibility guidelines.

---

## 7. Verification & Regression Results

1. **Model 3A Unit & Governance Tests (`backend/tests/test_identity_impersonation.py`):**
   - 10 passed out of 10 tests in 10.96s (`100% pass`).
   - Covered Test Fixtures 1–7, governance invariants, risk engine isolation, and FastAPI endpoint.
2. **Model 3B Regression Tests (`backend/tests/test_lookalike_pipeline.py`):**
   - 11 passed out of 11 tests (`100% pass`).
   - Frozen SHA-256 hash verified: `31224D67D9D97660A5DB20F5AC16CC1C24B8B22B86EC290240180F11C09D2559`.
3. **Web Frontend Production Build (`web`):**
   - `tsc -b && vite build`: Exited with code 0 (`✓ built in 28.01s`).
4. **Mobile TypeScript Verification (`mobile`):**
   - `npx tsc --noEmit`: Exited with code 0 (`0 errors`).
5. **Model Integrity:**
   - Model 1 (`phishing_baseline_v1`): SHA-256 verified untouched.
   - Model 2 (`bec_baseline_v1`): SHA-256 verified untouched.
   - Model 3B (`lookalike_domain_v1`): SHA-256 verified untouched.

---

## 8. Files Summary

### Files Created:
1. `ml/datasets/model3a/MODEL3A_DATASET_AUDIT.md`
2. `ml/evaluation/MODEL3A_BASELINE_EVALUATION.md`
3. `ml/inference/identity_impersonation_predictor.py`
4. `backend/app/schemas/identity.py`
5. `backend/app/services/identity_impersonation_service.py`
6. `backend/tests/test_identity_impersonation.py`
7. `PHASE9A_MODEL3A_REPORT.md`

### Files Modified:
1. `backend/app/services/risk_engine.py` (added `identity_risk: 0-15` and `evaluate_identity_risk`)
2. `backend/app/api/v1/endpoints/emails.py` (added `/identity-impersonation-detect` and integrated into `/analyze`)
3. `backend/app/api/v1/endpoints/cases.py` (integrated identity evidence into `get_case_details`)
4. `web/src/types/index.ts` (added `IdentityImpersonationEvidence` and `identity_impersonation_risk`)
5. `web/src/pages/InvestigationWorkspace.tsx` (added tab, score bar, and evidence card)
6. `mobile/src/screens/CaseDetailScreen.tsx` (added compact identity card and signals)

---

## 9. Next Recommended Phase

**Phase 9A is complete.**  
Per instructions, execution stops here. The recommended next step is **Phase 9B: Advanced Cross-Modal Correlation & Threat Vector Fusion**.
