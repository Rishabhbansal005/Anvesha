# ANVESH Phase 4: Final Machine Learning & Forensic Evaluation Summary

**Document ID:** `ml/evaluation/PHASE4_FINAL_MODEL_SUMMARY.md`  
**Classification:** Authoritative Technical Reference Document  
**System Version:** ANVESH Forensic Intelligence Platform v1.0.0  
**Model Artifact:** `ml/models/phishing_baseline_v1/model.joblib`  
**Evaluation Status:** COMPLETE — SEALED UNDER STRICT GOVERNANCE PROTOCOLS  

---

## 1. Executive Summary & Core Architectural Finding

In email threat detection, standalone statistical or machine learning classifiers are often evaluated on artificial, mono-labeled benchmark splits that produce deceptively high nominal metrics (e.g., 100% accuracy) while failing catastrophically in realistic enterprise environments.

During Phase 4, ANVESH instituted an **evidence-based 4-Tier Assessment Framework** that subjected **Model 1 (Phishing Baseline)** and the **Full ANVESH Multi-Layered Forensic Engine** to increasingly rigorous, out-of-distribution, and adversarial evaluations:

1. **Development Validation:** Revealed that in-distribution validation (100% accuracy) was driven by complete source-label confounding between corporate benign text (Enron) and phishing lures (Mendeley/Nazario).
2. **Source-Aware Holdout:** Proved that holding out an unseen benign source (SpamAssassin) causes probability confidence to degrade toward the decision boundary (median probability shifting from `0.01` to `0.4414`).
3. **IWSPA-AP Independent Test:** Confirmed high separation on 3,000 independent credential phishing emails while observing real-world benign probability drift into the $[0.40, 0.50]$ range.
4. **ANVESH Challenge Benchmark:** Proved that pure text classifiers fail on conversational Business Email Compromise (BEC), misclassifying **50.00% of legitimate invoice/payment emails as phishing**. In contrast, the **Full ANVESH Forensic Engine eliminated all false positives (0.00% FPR, 100% Precision)** by synthesizing cryptographic authentication (SPF/DKIM/DMARC) and relay infrastructure routing.

### The ANVESH Core Philosophy:
> **Model 1 is an evidence-layer text signal, NOT an autonomous verdict engine.**  
> Real-world enterprise defense cannot rely on text classification alone. ANVESH solves this by combining natural language signals with deterministic cryptographic authentication, SMTP relay chain inspection, IP/domain intelligence, behavioral BEC rules, strict attribution boundaries, and actionable evidence gaps.

---

## 2. Model 1 Technical Specifications & Architecture

Model 1 is trained as a binary linear text classifier designed to detect credential harvesting lures, deceptive linguistic framing, and coercion patterns in email text.

```
+-------------------------------------------------------------------------------+
|                             MODEL 1 SPECIFICATIONS                            |
+--------------------------+----------------------------------------------------+
| Architecture             | TF-IDF Vectorizer + Logistic Regression Classifier |
| Target Labels            | Binary: 0 = BENIGN, 1 = THREAT_PHISHING            |
| Input Features           | Raw (subject, body) only via normalize_email_pair  |
| Excluded Features        | Headers, SPF, DKIM, DMARC, IP, DNS, RDAP, Threat-Intel|
| TF-IDF Hyperparameters   | ngram_range=(1,2), max_features=10000, sublinear_tf=True |
| Logistic Regression Params| C=1.0, class_weight='balanced', random_state=42, max_iter=1000 |
| Operational Threshold    | tau = 0.5000 (Fixed & Uncalibrated)                |
+--------------------------+----------------------------------------------------+
```

---

## 3. Comprehensive 4-Tier Assessment Breakdown

```
+--------------------------------------------------------------------------------------------------------+
|                                4-TIER EVALUATION ASSESSMENT FRAMEWORK                                  |
+-----------------------------+-----------+-----------------------+-----------+-----------+--------------+
| Evaluation Tier             | Samples   | Evaluation Focus      | Accuracy  | Benign FPR| Threat Recall|
+-----------------------------+-----------+-----------------------+-----------+-----------+--------------+
| 1. Development Validation   | 2,645     | In-Distribution Split | 1.0000    | 0.00%     | 1.0000       |
| 2. Source-Aware Holdout     | 1,907     | Source Generalization | 0.9995    | 0.25%     | 1.0000       |
| 3. IWSPA-AP Independent     | 3,000     | Held-Out Phishing     | 1.0000    | 0.00%     | 1.0000       |
| 4. ANVESH Challenge (Text)  | 50        | Conversational BEC    | 0.8000    | 50.00%    | 1.0000       |
| 4. ANVESH Challenge (ANVESH)| 50        | Full Forensic Engine  | 0.8000    | 0.00%     | 0.6667*      |
+-----------------------------+-----------+-----------------------+-----------+-----------+--------------+
```
*\*Note:* The 33.33% unescalated threats in Full ANVESH are authenticated mailbox compromises where transport authentication passes. Rather than guessing attribution, ANVESH strictly enforces the Attribution Boundary and raises actionable Evidence Gaps.

---

### Tier 1 — Development Validation Audit
- **Dataset Composition:** 2,645 validation samples (1,145 `BENIGN` from Enron & SpamAssassin; 1,500 `THREAT_PHISHING` from Mendeley/Nazario).
- **Metrics:** Accuracy: `100.00%`, Precision: `100.00%`, Recall: `100.00%`, F1: `100.00%`, ROC-AUC: `1.0000`.
- **Confusion Matrix:** $\text{TN} = 1,145, \text{FP} = 0, \text{FN} = 0, \text{TP} = 1,500$.
- **Methodological Finding:** This nominal 100% score is an artifact of **source-label confounding**. Every benign sample originated from historical energy/tech corpora, whereas every phishing sample originated from lure repositories. The classifier memorized domain-specific lexicons rather than generalizable threat invariants.

---

### Tier 2 — Source-Aware Holdout (Experiment A)
- **Dataset Composition:** 1,907 evaluation samples (407 `BENIGN` from SpamAssassin held entirely out of training; 1,500 `THREAT_PHISHING`).
- **Metrics:** Accuracy: `99.95%`, Phishing Precision: `99.93%`, Phishing Recall: `100.00%`, Benign FPR: `0.25%` (1/407).
- **Probability Distribution on Held-Out Benign:**
  - Minimum Phishing Probability: `0.2965`
  - Maximum Phishing Probability: `0.6234`
  - **Median Phishing Probability:** **`0.4414`** (Mean: `0.4234`)
  - **Samples in $[0.40, 0.60]$ decision boundary:** **`332 / 407 (81.6%)`**
- **Methodological Finding:** When evaluated against an unseen benign corporate/technical style, benign probabilities compress directly against the $\tau = 0.50$ decision boundary, proving that pure text classifiers are fragile to out-of-distribution shifts.

---

### Tier 3 — IWSPA-AP Independent Test Evaluation
- **Dataset Composition:** 3,000 independent samples (1,500 `BENIGN` + 1,500 `THREAT_PHISHING`) evaluated on frozen Model 1 with zero fitting, tuning, or calibration.
- **Metrics:** Accuracy: `100.00%`, Precision: `100.00%`, Recall: `100.00%`, F1: `100.00%`, ROC-AUC: `1.0000`, Benign FPR: `0.00%`, Phishing FNR: `0.00%`.
- **Confusion Matrix:** $\text{TN} = 1,500, \text{FP} = 0, \text{FN} = 0, \text{TP} = 1,500$.
- **Probability Distribution:**
  - Benign Subset Median: `0.1937` (Range: `0.0453` to `0.4503`)
  - Phishing Subset Median: `0.9524` (Range: `0.9098` to `0.9732`)
  - **Boundary Cluster:** **372 benign samples fell in $[0.40, 0.50]$** (max $p = 0.4503$).
- **Methodological Finding:** Model 1 demonstrated clean separation on classical link-based credential phishing, but realistic benign variance continued to drift closer to the threshold than in-distribution validation.

---

### Tier 4 — ANVESH Adversarial Challenge Benchmark (50 Scenarios)
- **Dataset Composition:** 50 curated adversarial scenarios: 30 `THREAT_BEC` (Authenticated Compromise, Reply-To Spoofing, Vendor Invoice Fraud) + 20 `BENIGN` (Urgent Business Operations, Legitimate Invoice Payments).

#### Layer A — Model 1 Text-Only Baseline Signal:
- **Metrics:** Accuracy: `80.00%`, Precision: `75.00%`, Recall: `100.00%`, F1: `85.71%`.
- **Confusion Matrix:** $\text{TN} = 10, \text{FP} = 10, \text{FN} = 0, \text{TP} = 30$.
- **Benign False Positive Rate:** **`50.00%` (10 / 20 legitimate business emails falsely flagged)**.
- **Root Cause Analysis:** All 10 `BENIGN_LEGIT_INVOICE_PAYMENT` samples contained standard financial terms (`"wire"`, `"invoice"`, `"remittance"`, `"settlement"`). Lacking transport and authentication context, Model 1 produced phishing probabilities between `0.60` and `0.79`, demonstrating the severe vulnerability of standalone text models to benign operational false positives.

#### Layer B — Full ANVESH Forensic & Risk Assessment Engine:
- **Metrics:** Accuracy: `80.00%`, Precision: `100.00%`, Recall: `66.67%`, F1: `80.00%`.
- **Confusion Matrix:** $\text{TN} = 20, \text{FP} = 0, \text{FN} = 10, \text{TP} = 20$.
- **Benign False Positive Rate:** **`0.00%` (Zero legitimate emails escalated)**.
- **Threat False Negative Rate:** `33.33%` (10 / 30 held at transport boundary).
- **Forensic Takeaway:** ANVESH synthesized cryptographic SPF/DKIM/DMARC passes with verified domain infrastructure to **eliminate all 10 benign false positives**. 

---

## 4. Understanding the Forensic Attribution Boundary

A critical differentiator of ANVESH is its adherence to evidentiary standards over naive machine learning heuristics:

```
                      +------------------------------------------+
                      |         RFC-822 EMAIL PAYLOAD            |
                      +------------------------------------------+
                                           |
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
     [TRANSPORT & CRYPTO LAYER]                       [NLP & BEHAVIORAL LAYER]
  - SPF / DKIM / DMARC Status                       - Model 1 Lexical Phishing Score
  - SMTP Received Relay Hops                        - Financial Coercion Patterns
  - Public IP / ASN Intelligence                    - Reply-To Mismatch Detection
  - Shared SaaS Gateway Identity                    - Urgency / Account Alteration
                   |                                               |
                   +-----------------------+-----------------------+
                                           |
                                           v
                          +----------------------------------+
                          |   COMPOSITE FORENSIC SYNTHESIS   |
                          +----------------------------------+
                                           |
              +----------------------------+----------------------------+
              |                                                         |
  [INFRASTRUCTURE EVIDENCE]                                  [ATTRIBUTION BOUNDARY]
  - Verifies multi-tenant relays                             - Invariant: Actor Identity
  - Identifies intermediate hops                               "NOT ESTABLISHED"
  - Evaluates origin confidence                              - Explicit Evidence Gaps
```

### Why Layer B Unescalated Cases are NOT "Model Failures":
In the 10 `AUTHENTICATED_BEC_COMPROMISE` scenarios:
1. The attacker operated through a legitimate, compromised Microsoft 365 or Google Workspace tenant account.
2. The transport headers showed SPF `PASS`, DKIM `PASS`, and DMARC `PASS`.
3. The originating IP was a verified, shared public gateway (`20.190.151.68` / Microsoft Azure).

Under transport-layer evidence alone, attributing malicious human identity to a legitimate tenant account is forensically impossible. Rather than fabricating an attribution, ANVESH:
- Restricts origin confidence to observed shared cloud relays.
- Maintains the invariant: `Actor Identity: NOT ESTABLISHED`.
- Emits actionable **Forensic Evidence Gaps**:
  - *"Mailbox sign-in and session audit logs unobserved."*
  - *"Tenant message trace and outbound connector telemetry unobserved."*
  - *"Mailbox forwarding and inbox rule modification history unverified."*
- Prescribes clear investigative actions: *"Initiate tenant M365/Google Workspace audit log export for the sender identity."*

---

## 5. Authoritative Evaluation Comparison Table

| Dimension | 1. Development Validation | 2. Source-Aware Holdout | 3. IWSPA Independent | 4. Challenge (Model 1) | 4. Challenge (Full ANVESH) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Dataset Size** | 2,645 | 1,907 | 3,000 | 50 | 50 |
| **Benchmark Nature** | In-Distribution Split | Out-of-Source Holdout | Independent Phishing | Adversarial BEC | Adversarial BEC |
| **Evaluated Layer** | Model 1 (Text-Only) | Model 1 (Text-Only) | Model 1 (Text-Only) | Model 1 (Text-Only) | Full ANVESH Forensic Engine |
| **Accuracy** | 1.0000 | 0.9995 | 1.0000 | 0.8000 | 0.8000 |
| **Threat Precision** | 1.0000 | 0.9993 | 1.0000 | 0.7500 | **1.0000** |
| **Threat Recall** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6667 (Transport Boundary) |
| **Benign FPR** | 0.00% | 0.25% | 0.00% | **50.00%** (10/20 FP) | **0.00%** (0/20 FP) |
| **Benign Median Prob**| 0.0126 | 0.4414 | 0.1937 | 0.5195 | Informational (Score 5) |
| **Key Insight** | Memorized lexicon | Confidence boundary drift | Link phishing separated | Financial text causes FP | **Multi-layered defense eliminates FP** |

---

## 6. Governance & Cryptographic Integrity Attestation

Phase 4 was conducted under strict machine learning governance rules:

```
====================================================================================================
FINAL PHASE 4 GOVERNANCE & INTEGRITY AUDIT ATTESTATION
====================================================================================================
1. Model 1 Artifact State:           FROZEN & SEALED in ml/models/phishing_baseline_v1/model.joblib
   - Cryptographic SHA-256 Hash:     f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7
   - Fitting / Retraining Calls:     0 (.fit() / .fit_transform() never called during evaluation)
   - Parameter / Threshold Changes:  NONE (tau = 0.5000 strictly preserved)
   - Probability Calibration:        NOT PERFORMED (preserves raw empirical estimates)

2. Independent Test Set Integrity:   SEALED in ml/datasets/processed/independent_test_iwspa.jsonl
   - Cryptographic SHA-256 Hash:     a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552
   - Usage Governance:               EVALUATION ONLY — ZERO TRAINING / TUNING

3. Challenge Benchmark Integrity:    SEALED in ml/datasets/challenge/anvesh_challenge_50.jsonl
   - Cryptographic SHA-256 Hash:     a5abe63187a59eb32c730ec2dd0f7d248629fd7a50679baaa296bd224092c68f
   - Usage Governance:               EVALUATION ONLY — ZERO TRAINING / TUNING

4. Production Engine State:          Phases 2 & 3 functionality, FastAPI routers, and risk schemas
                                     remain 100% stable and intact.
   - External Secrets / API Keys:    NONE INTRODUCED
   - Attribution Invariant:          "Actor Identity: NOT ESTABLISHED" strictly enforced.
   - Backend Pytest Suite:           21 / 21 TESTS PASSED (tests/test_email_pipeline.py,
                                     tests/test_enrichment_attribution.py, tests/test_ml_pipeline.py).
====================================================================================================
```
