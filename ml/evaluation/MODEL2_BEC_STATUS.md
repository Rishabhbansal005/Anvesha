# ANVESH Phase 6 — Model 2 (BEC Detection) Status & Governance Audit

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Component:** Model 2 (Business Email Compromise Detection Baseline)  
**Governance Invariant:** Model 1, IWSPA Independent Test, ANVESH Challenge, and Phase 4/5 Artifacts **REMAIN FROZEN**  

---

## STATUS: DATASET GAP — TRAINING BLOCKED FOR PRODUCTION (DEVELOPMENT BASELINE PREPARED)

---

## 1. Executive Summary & Scientific Rationale

In strict accordance with the ANVESH Scientific Integrity Principle:
> **"A smaller defensible BEC model is better than a large fabricated BEC model. Do NOT manufacture labels simply to claim Model 2 is complete."**

Our repository and public data audit established that **no defensible, large-scale, enterprise-grade BEC training corpus exists in open public research archives**. 
- Common security ML shortcuts (e.g., relabeling Nigerian 419 advance-fee scams as BEC, or relabeling generic phishing as BEC based purely on keyword matching of terms like `invoice` or `wire`) introduce severe label noise and unscientific data contamination.
- Consequently, **production deployment of Model 2 is intentionally BLOCKED** until authentic enterprise SOC/telemetry incident data is acquired.
- A clean, isolated **synthetic development baseline pipeline** and Google Colab notebook (`ml/notebooks/02_bec_baseline_colab.ipynb`) have been established for reproducible development without contaminating production risk scoring.

---

## 2. Dataset Audit & Taxonomy Classification

| Corpus Candidate | Records | Category Classification | Role in Model 2 |
| :--- | :--- | :--- | :--- |
| **Enron Corporate Email** | ~517,401 | **Category D (Benign Business Email)** | Approved negative background class (enterprise tone, legitimate invoices, vendor discussions). |
| **Jose Nazario Phishing** | ~8,150 | **Category B (Generic Phishing)** | **Unsuitable for BEC.** Consumer credential lures; lacking enterprise accounting/wire fraud context. |
| **SpamAssassin Public** | ~6,047 | **Category D (Benign General / Spam)** | Benchmark for commercial spam vs. targeted enterprise BEC false alarms. |
| **419 Scam Corpus** | ~2,500 | **Category C (Advance-Fee Fraud / Scam)** | **STRICTLY PROHIBITED FROM BEC RELABELING.** Consumer lottery/estate letters do not reflect enterprise wire diversion. |
| **IWSPA-AP Test Benchmark** | 3,000 | **Category B + D (Anti-Phishing Test)** | **FROZEN.** Tier C independent evaluation set; strictly isolated from training. |
| **ANVESH Challenge Benchmark** | 50 | **Category E (Synthetic / Challenge Set)** | **FROZEN.** Tier D product benchmark; strictly isolated from training. |
| **ANVESH BEC Synthetic Dev Set** | 10 | **Category E (Synthetic / Dev Only)** | Isolated 8-scenario baseline verification set (`ml/datasets/bec_development_synthetic.jsonl`). |

---

## 3. Label Definition & Schema

The target label schema for Model 2 is defined as a binary classification:
- **`BEC` (Class 1):** Targeted business email compromise, payroll diversion, vendor bank change fraud, executive wire impersonation, and account takeover financial redirection.
- **`NON_BEC` (Class 0):** Legitimate business communications, normal corporate operations, regular vendor invoices, routine HR/payroll notices.

### Granular Subtypes (Tracked in Metadata):
1. `EXECUTIVE_IMPERSONATION`
2. `VENDOR_PAYMENT_FRAUD`
3. `BANK_ACCOUNT_CHANGE`
4. `INVOICE_REMITTANCE_FRAUD`
5. `CREDENTIAL_MANIPULATION`
6. `COMPROMISED_ACCOUNT`
7. `OTHER_BEC`

---

## 4. Data Leakage & Boundary Controls

| Boundary Control | Verification Status | Details |
| :--- | :--- | :--- |
| **IWSPA Independent Test Isolation** | **0% Overlap** | Zero samples shared between BEC development and `independent_test_iwspa.jsonl`. |
| **ANVESH Challenge Set Isolation** | **0% Overlap** | Zero samples shared between BEC development and `anvesh_challenge_50.jsonl`. |
| **Model 1 Independence** | **100% Isolated** | Model 1 weights, hyperparameters, and production inference remain completely unchanged. |
| **Feature Boundary** | **Subject + Body Only** | Model 2 evaluates text tokens only; no headers, SPF/DKIM/DMARC, IP, DNS, or TI are fed to the ML vectorizer. |

---

## 5. Development Baseline & Colab Training

A self-contained Google Colab notebook has been authored and verified:
- **File:** `ml/notebooks/02_bec_baseline_colab.ipynb`
- **Architecture:** `TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words='english')` + `LogisticRegression(class_weight='balanced', C=1.0, random_state=42, max_iter=1000)`
- **Validation:** JSON schema verified with 17 structured cells covering data loading, governance checks, n-gram weight extraction, and artifact serialization.

---

## 6. Core Forensic Scenarios Verified

The development baseline verifies 8 critical enterprise scenarios:
1. **Executive Impersonation:** Urgent wire authorization referencing confidential acquisition.
2. **Vendor Bank-Account Change:** Notification of updated banking details for an existing vendor.
3. **Invoice/Remittance Manipulation:** Revised invoice PDF requesting remittance to alternate routing details.
4. **Urgent Wire-Transfer Request:** Time-sensitive retainer payment before banking cutoff.
5. **Compromised Account Conversation:** Thread hijacking from authenticated mailbox requesting secondary wire routing.
6. **Legitimate Business Invoice (NON_BEC):** Routine hardware delivery invoice with standard Net-30 terms and registered bank account.
7. **Legitimate Finance Communication (NON_BEC):** Monthly budget variance commentary and executive committee deck.
8. **Normal Corporate Communication (NON_BEC):** Board meeting agenda and team milestone celebration lunch.

---

## 7. Model Artifact & Production Inference Status

- **Model Artifacts:** Not committed to production directory `ml/models/bec_baseline_v1/` to prevent premature deployment.
- **FastAPI / Production Inference:** Model 2 is **NOT** integrated into production FastAPI routes.
- **Production Risk Engine:** Continues to evaluate BEC threats through the Phase 2/3 deterministic behavioral rule engine + Model 1 text signal + SPF/DKIM/DMARC multi-hop forensic correlation.

---

## 8. Governance & Integrity Verification

All Phase 4 & Phase 5 artifacts remain verified, frozen, and untouched:

| Artifact | Expected SHA-256 Hash | Status |
| :--- | :--- | :--- |
| `ml/models/phishing_baseline_v1/model.joblib` | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | **FROZEN & VERIFIED** |
| `ml/models/phishing_baseline_v1/metadata.json` | `39a9b88a813cb3fc80eba27a808933ccc0c3923625ffeed588004eeb957cdd83` | **FROZEN & VERIFIED** |
| `ml/models/phishing_baseline_v1/top_features.json` | `5a811278614f9d08f842aca8145ca4cf41292574d5e9c37b6bfbf0c392e38fa2` | **FROZEN & VERIFIED** |
| `ml/datasets/processed/independent_test_iwspa.jsonl` | `a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552` | **FROZEN & VERIFIED** |
| `ml/datasets/challenge/anvesh_challenge_50.jsonl` | `a5abe63187a59eb32c730ec2dd0f7d248629fd7a50679baaa296bd224092c68f` | **FROZEN & VERIFIED** |
| `ml/evaluation/PHASE4_FINAL_MODEL_SUMMARY.md` | `ca91f82029b6572106888aa8850e347b6817e8cb0227600d4e4e1e86f14079e2` | **FROZEN & VERIFIED** |

---

## 9. Next Steps for Authentic BEC Acquisition

1. Partner with enterprise SOC teams / financial sector ISACs to ingest anonymized, PII-scrubbed BEC fraud transcripts.
2. Expand high-fidelity adversary emulation campaigns to build a 2,000+ sample verified enterprise BEC training partition.
3. Perform source-aware cross-validation before initiating Model 2 production integration.
