# ANVESH Phase 9B — Cross-Modal Threat Correlation & Forensic Signal Fusion Report

**Document Status:** Production Verified  
**Milestone:** Phase 9B — Explainable Forensic Signal Fusion Layer  
**Target Platform:** ANVESH Forensic Intelligence Platform (Web & Mobile Incident Response Companion)  
**Governance Invariant:** Zero Model Retraining; Frozen Weights & Hashes; Anti-Double-Counting Enforced; Non-Attribution Boundary Immutable  

---

## 1. Executive Summary

Phase 9B introduces the **ANVESH Forensic Signal Fusion Engine** (`anvesh_forensic_fusion_v1`), an explainable cross-modal evidence synthesis layer. Rather than introducing a black-box machine learning classifier or naively averaging anomaly scores, Phase 9B synthesizes disparate technical observables into a unified, analyst-ready forensic assessment:

- **Model 1 (Phishing NLP):** Linguistic and threat-oriented semantic vectors (0–30 normalized to 0–12 pts).
- **Model 2 (BEC Intent):** Urgency, financial coercion, and invoice redirection indicators (0–12 pts).
- **Model 3A (Identity Impersonation):** Executive spoofing, external freemail misuse, and Reply-To discrepancies (0–20 pts).
- **Model 3B (Lookalike Domain):** Random forest domain resemblance and homoglyph/typosquat indicators (0–15 pts).
- **Cryptographic Authentication:** RFC-compliant SPF, DKIM, and DMARC verification (0–15 pts).
- **Transport Trajectory:** SMTP Received hop traversal and origin confidence assessment (0–6 pts).
- **Threat Intelligence:** IP reputation abuse scores, TOR exit relays, and commercial proxy traversal (0–15 pts).
- **Campaign Intelligence:** Observable clustering, shared IOC correlation, and multi-case linkage (0–10 pts).

---

## 2. Core Architectural Principles & Invariants

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                   INCOMING OBSERVABLES                                  │
│  [Model 1 & 2 Content]  [Model 3A Identity]  [Model 3B Domain]  [SPF/DKIM/DMARC Auth]   │
│  [SMTP Trajectory]      [Threat Intel IP]    [Campaign Engine]  [Evidence Gaps]         │
└────────────────────────────────────────┬────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                        ANTI-DOUBLE-COUNTING INDEPENDENCE GROUPS                         │
│  - DOMAIN_IDENTITY (Cap: 15)       - IDENTITY_AUTHORITY (Cap: 15)                       │
│  - TRANSPORT_REPLY_TO (Cap: 15)    - CONTENT_PRESSURE (Cap: 15)                         │
│  - CRYPTOGRAPHIC_AUTH (Cap: 15)    - INTEL_REPUTATION (Cap: 12)                         │
│  - INTEL_PROXY (Cap: 8)            - CAMPAIGN_CLUSTER (Cap: 10)                         │
└────────────────────────────────────────┬────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                             CAPPED CATEGORICAL SCORING                                  │
│  Content: 0–20  │  Identity: 0–20  │  Infra: 0–20  │  Auth: 0–15  │  Intel: 0–15  │ Cmp: 0–10│
│                              TOTAL SYNTHESIZED SCORE: 0 - 100                           │
└────────────────────────────────────────┬────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           CONTRADICTION & CONFLICT RESOLUTION                           │
│  - AUTH_PASS_BUT_IDENTITY_SUSPICIOUS (Compromised account / lookalike domain)           │
│  - MALICIOUS_IP_BENIGN_CONTENT (Egress proxy / multi-tenant routing)                    │
│  - BENIGN_INFRASTRUCTURE_SUSPICIOUS_IDENTITY (SaaS executive spoofing)                  │
└────────────────────────────────────────┬────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          MANDATORY ATTRIBUTION BOUNDARY                                 │
│  Actor Identity: NOT ESTABLISHED | Technical Observables Only | Zero Legal Liability    │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Zero Model Retraining Invariant & Artifact Verification
Model 1, Model 2, Model 3A, and Model 3B model weights, pipeline code, and serialization artifacts remain completely frozen. All SHA-256 hashes have been verified from the actual filesystem on disk, matching the established project baselines:

| Component | Model Name | Artifact File Path | SHA-256 Hash | Status |
|---|---|---|---|---|
| **Model 1** | Phishing Baseline (`anvesh_phishing_baseline`) | `ml/models/phishing_baseline_v1/model.joblib` | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | **FROZEN** |
| **Model 2** | BEC Baseline (`bec_baseline_v1`) | `ml/models/bec_baseline_v1/model.joblib` | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` | **FROZEN** |
| **Model 3A** | Governed Deterministic Identity Impersonation Baseline (`model3a_deterministic_v1`) | `ml/inference/identity_impersonation_predictor.py` | `N/A (Deterministic Implementation)` | **FROZEN** |
| **Model 3B** | Lookalike Domain Model (`lookalike_domain_v1`) | `ml/models/lookalike_domain_v1/model.joblib` | `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559` | **FROZEN** |

> [!NOTE]
> Dataset and challenge benchmarks (e.g. IWSPA dataset `a3b984...` and ANVESH Challenge `a5abe6...`) are distinct testing assets and are not confused with production model binaries. Model 3A is a governed deterministic baseline engine without serialized binary weights.

### 2.2 Strict Anti-Double-Counting Mechanism
Overlapping observables (e.g. Model 3B flag for lookalike domain `paypa1.com` and Model 3A flag for display-name domain mismatch `paypa1.com`) belong to the shared independence group `DOMAIN_IDENTITY`. The engine caps the contribution of any single independence group to a maximum of 15 points, preventing correlated signals from inflating the overall score.

### 2.3 Contradiction & Conflict Resolution
The engine actively detects when evidence points in conflicting directions:
- **`AUTH_PASS_BUT_IDENTITY_SUSPICIOUS`**: Triggered when SPF/DKIM/DMARC pass, but identity or behavioral risk remains high. Resolution note explicitly informs the analyst: *"Authentication verification confirms sending server authorization only. Compromised corporate accounts, delegated relays, and lookalike domains with valid DNS records routinely pass SPF/DKIM."*
- **`MALICIOUS_IP_BENIGN_CONTENT`**: Origin gateway flagged in abuse databases, but message body and identity headers are benign.
- **`BENIGN_INFRASTRUCTURE_SUSPICIOUS_IDENTITY`**: Legitimate cloud hosting (Microsoft 365, Google Workspace) used with spoofed display names.

### 2.4 Immutable Attribution Boundary
The forensic fusion layer guarantees that:
- `actor_identity` is strictly `"NOT ESTABLISHED"`.
- Never outputs "Attacker", "Attacker identity", or "Attacker physical location".
- Emits explicit disclaimers: *"Forensic Signal Fusion synthesizes technical observables and model evidence only. It does not establish attacker identity, legal liability, or actor intent."*

---

## 3. Implementation Details

### 3.1 Schemas (`backend/app/schemas/fusion.py`)
- `EvidenceContribution`: Models individual contributions with `category`, `signal`, `severity`, `contribution`, `independence_group`, `source`, `evidence_id`, and `parent_evidence_id`.
- `EvidenceContradiction`: Models detected conflicts with `type`, `description`, `conflicting_signals`, and `resolution_note`.
- `CategoryBreakdownItem`: Models score and maximum cap for each category.
- `FusionAttribution`: Enforces `"actor_identity": "NOT ESTABLISHED"`, `observed_infrastructure`, `origin_confidence`, and `attribution_boundary`.
- `ForensicFusionRequest`: Pydantic input schema for standalone `/forensic-fusion` evaluations.
- `ForensicFusionResult`: Consolidated output model returned by API and persisted in case records.

### 3.2 Fusion Service (`backend/app/services/forensic_fusion_service.py`)
- Implements `ForensicFusionService.fuse()` evaluating the 6 capped categories.
- Tracks `group_totals` by `independence_group` to prevent double-counting.
- Segregates findings into `primary_signals` (top deterministic findings) and `supporting_signals` (corroborating context).
- Computes `fusion_confidence` (`HIGH`, `MEDIUM`, `LOW`) based on the count of active independent categories and surfaces confidence rationales.
- Formulates deterministic forensic interpretations based on category scores and contradiction presence.

### 3.3 API Endpoints
- **`POST /api/v1/emails/forensic-fusion`**: Standalone cross-modal synthesis endpoint accepting `ForensicFusionRequest`.
- **`POST /api/v1/emails/analyze`**: Full forensic ingestion pipeline invokes `forensic_fusion_service.fuse(...)` and returns `"fusion": fusion_res`.
- **`GET /api/v1/cases/{case_id}`**: Retrieves case details and computes real-time forensic fusion across all saved case observables and ML signals.

### 3.4 Web User Experience (`web/src/pages/InvestigationWorkspace.tsx`)
- **Overview Tab:** Calm, structured `FORENSIC SIGNAL FUSION` card displaying synthesized score, confidence pill, synthesized interpretation, contradiction alerts, mini category progress bars, and `"Actor Identity: NOT ESTABLISHED"` badge.
- **Dedicated Navigation Section (`activeSection === 'fusion'`):**
  - Synthesized Score card with risk level and anti-double-counting tag.
  - Confidence rating with evidence coverage rationales.
  - Primary signals vs Supporting signals comparative panel.
  - 6-Category scoring breakdown with visual progress bars.
  - Contradiction & Conflict Resolution panel with forensic invariant notes.
  - Non-Double-Counted Evidence Contributions table detailing category, signal, independence group, points, severity, and source.
  - Mandatory attribution boundary and invariant disclaimer.

### 3.5 Mobile Companion (`mobile/src/screens/CaseDetailScreen.tsx`)
- Executive `FORENSIC ASSESSMENT` section positioned directly under the case header.
- Clean, compact styling adhering to Incident Response Companion ergonomics:
  - Confidence pill (`HIGH` / `MEDIUM` / `LOW`).
  - Synthesized score badge (`X/100`).
  - Forensic interpretation narrative.
  - Contradiction warning banner when conflicting observables exist.
  - 2x3 mini category grid with progress meters.
  - Strict `"Actor Identity: NOT ESTABLISHED"` boundary pill.

---

## 4. Verification & Testing Matrix

### 4.1 Unit & Governance Test Suite (`tests/test_forensic_fusion.py`)
| Test Fixture | Purpose | Result |
|---|---|:---:|
| `test_1_multi_signal_high_risk_synthesis` | Multi-signal aggregation across all 6 categories, category caps verified | **PASSED** |
| `test_2_compromised_mailbox_auth_pass_identity_deception` | Cryptographic auth PASS + identity deception triggers `AUTH_PASS_BUT_IDENTITY_SUSPICIOUS` | **PASSED** |
| `test_3_benign_internal_email` | Clean internal email yields low risk (< 15) and zero contradictions | **PASSED** |
| `test_4_anti_double_counting_domain_identity` | Lookalike domain + M3A mismatch respects `DOMAIN_IDENTITY` cap of 15 | **PASSED** |
| `test_5_malicious_ip_benign_content_contradiction` | Malicious origin IP + benign text triggers `MALICIOUS_IP_BENIGN_CONTENT` | **PASSED** |
| `test_6_contradiction_schema_and_resolution_notes` | Validates contradiction schema, conflict list, and resolution guidance | **PASSED** |
| `test_7_sparse_evidence_reduces_confidence` | Isolated indicator reduces `fusion_confidence` to `LOW` | **PASSED** |
| `test_8_coordinated_campaign_correlation` | Campaign evidence adds points under `CAMPAIGN` category (cap 10) | **PASSED** |
| `test_9_compromised_mailbox_non_attribution_invariant` | Verifies `actor_identity == "NOT ESTABLISHED"` and disclaimer presence | **PASSED** |
| `test_10_empty_minimal_inputs_robustness` | Evaluates empty/None input handling without raising exceptions | **PASSED** |

### 4.2 Full Backend Regression Suite
- Total tests executed: **48 tests**
  - `test_forensic_fusion.py`: 10 passed
  - `test_identity_impersonation.py`: 10 passed
  - `test_lookalike_pipeline.py`: 11 passed
  - `test_campaign_intelligence.py`: 17 passed
- Result: **48 PASSED (100%), 0 FAILED** in 60.46s.

### 4.3 Web Production Build
- Command: `tsc -b && vite build`
- Result: **0 errors, built successfully in 6.21s** (`dist/assets/index-BhrdGakN.js`, 373.05 kB).

### 4.4 Mobile TypeScript Typecheck
- Command: `npx tsc --noEmit`
- Result: **0 errors, clean exit with code 0**.

---

## 5. Conclusion & Operational Readiness

Phase 9B completes the multi-modal evidence synthesis layer for ANVESH. Analysts on both Web and Mobile now receive a transparent, mathematically bounded, and legally sound forensic synthesis that highlights root technical causes, resolves evidential contradictions, enforces strict anti-double-counting, and preserves the mandatory non-attribution boundary.
