# ANVESH IWSPA-AP Independent Test Evaluation Report
**Document ID:** `ml/evaluation/IWSPA_INDEPENDENT_EVALUATION.md`  
**Generated:** September 6, 2026  
**Status:** `INDEPENDENT_EVALUATION_COMPLETE`  
**Target Dataset:** `ml/datasets/processed/independent_test_iwspa.jsonl` (3,000 samples)  
**Evaluated Artifact:** `ml/models/phishing_baseline_v1/model.joblib` (SHA-256: `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7`)

---

## 1. Executive Summary & Governance Compliance Statement

> [!IMPORTANT]
> *"These results are from a frozen Model 1 artifact evaluated once on a held-out independent test set. No training, tuning, threshold selection, or calibration was performed using IWSPA."*

### Cryptographic File Integrity Verification
- **IWSPA Dataset SHA-256 (Pre & Post Evaluation):** `a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552` (Unchanged)
- **Model 1 Artifact SHA-256 (Pre & Post Evaluation):** `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` (Unchanged)
- **ANVESH Challenge Benchmark (`anvesh_challenge_50.jsonl`):** **STRICTLY NOT ACCESSED (0 bytes read)**.
- **Fitting Operations:** **0 `.fit()` / `.fit_transform()` calls executed.**

---

## 2. Independent Dataset Composition

| Label Category | Sample Count | Percentage | Source Representation |
| :--- | :---: | :---: | :--- |
| **`BENIGN`** | **1,500** | 50.00% | IWSPA-AP Legitimate Email Benchmark |
| **`THREAT_PHISHING`** | **1,500** | 50.00% | IWSPA-AP Phishing Attack Corpus |
| **Total Independent Test** | **3,000** | **100.00%** | 100% Held-out from all training and validation |

---

## 3. Evaluation Methodology

1. **Input Interface:** Model 1 received strictly `(subject, body)`.
2. **Text Preprocessing:** Deterministic tokenization (`normalize_email_pair`) applied identically to training.
3. **No External Signals:** Zero access to headers, SPF, DKIM, DMARC, IP/GeoIP, DNS, RDAP, VirusTotal, AbuseIPDB, or risk scores.
4. **Decision Threshold:** Evaluated at the default operational threshold $\tau = 0.50$.

---

## 4. Overall Independent Test Metrics

| Metric | Measured Score | Percentage | Operational Significance |
| :--- | :---: | :---: | :--- |
| **Accuracy** | **1.0000** | 100.00% | Overall correct classification rate |
| **Phishing Precision** | **1.0000** | 100.00% | Positive predictive value for phishing |
| **Phishing Recall** | **1.0000** | 100.00% | Sensitivity to phishing threats |
| **F1-Score** | **1.0000** | 100.00% | Harmonic mean of precision and recall |
| **ROC-AUC** | **1.0000** | — | Area under the ROC curve |
| **Benign Specificity** | **1.0000** | 100.00% | True negative rate ($\text{TN}/(\text{TN}+\text{FP})$) |
| **Benign False Positive Rate** | **0.0000** | 0.00% | Proportion of benign emails falsely flagged |
| **Phishing False Negative Rate**| **0.0000** | 0.00% | Proportion of phishing emails missed |

### Independent Confusion Matrix
| | Predicted BENIGN (0) | Predicted PHISHING (1) | Total Actual |
| :--- | :---: | :---: | :---: |
| **Actual BENIGN (0)** | **1,500** (TN) | **0** (FP) | 1,500 |
| **Actual PHISHING (1)** | **0** (FN) | **1,500** (TP) | 1,500 |
| **Total** | 1,500 | 1,500 | **3,000** |

---

## 5. Model Phishing Probability Analysis

> [!NOTE]
> Probabilities are empirical model estimates from the logistic sigmoid function and have **not been formally calibrated**.

- **Overall Probability Metrics:**
  - Minimum: `0.0453`
  - Maximum: `0.9732`
  - Median: `0.6801`
  - Mean: `0.5927`
- **Benign Subset (1,500 samples):**
  - Minimum: `0.0453`
  - Maximum: `0.4503`
  - **Median: `0.1937`** (Mean: `0.2353`)
- **Phishing Subset (1,500 samples):**
  - Minimum: `0.9098`
  - Maximum: `0.9732`
  - **Median: `0.9524`** (Mean: `0.9502`)

### Probability Bin Distribution

| Probability Range | Actual BENIGN Count | Actual PHISHING Count | Total Samples | Operational Significance |
| :---: | :---: | :---: | :---: | :--- |
| **0.00 – 0.10** | 383 (25.5%) | 0 (0.0%) | 383 | High-confidence benign |
| **0.10 – 0.20** | 395 (26.3%) | 0 (0.0%) | 395 | Moderate-confidence benign |
| **0.20 – 0.30** | 291 (19.4%) | 0 (0.0%) | 291 | Low-confidence benign |
| **0.30 – 0.40** | 59 (3.9%) | 0 (0.0%) | 59 | Borderline benign |
| **0.40 – 0.50** | **372** (24.8%) | 0 (0.0%) | 372 | **Critical boundary cluster** ($p \le 0.4503$) |
| **0.50 – 0.90** | 0 (0.0%) | 0 (0.0%) | 0 | Clear decision margin |
| **0.90 – 1.00** | 0 (0.0%) | **1,500** (100.0%) | 1,500 | High-confidence phishing |

- **Samples near decision boundary $[0.40, 0.60]$:** **`372`** (all benign, max $p = 0.4503$).

---

## 6. Forensic Interpretation & Cross-Corpus Comparison

### Comparison Across All Three Evaluation Phases

| Metric / Attribute | Development Validation (Mixed) | Source-Aware Holdout (Exp B) | IWSPA-AP Independent Test |
| :--- | :---: | :---: | :---: |
| **Sample Count** | 2,645 | 4,909 | **3,000** |
| **Accuracy** | 1.0000 | 0.3056 *(Catastrophic collapse)* | **1.0000** |
| **Benign FPR** | 0.00% | 100.00% | **0.00%** |
| **Benign Median Proba** | **0.0126** *(Overconfident)* | **0.9250** *(Misclassified)* | **0.1937** *(Realistic drift)* |
| **Boundary Cluster $[0.40, 0.60]$**| **0** | **0** | **372 (12.4% of total)** |

### Key Forensic Insights:
1. **Realistic Probability Drift Observed:**
   On the development validation set (Enron corporate memos), the model exhibited extreme overconfidence ($p_{\text{median}} = 0.0126$). On the out-of-distribution IWSPA-AP benchmark, benign email probabilities drifted to a realistic median of **`0.1937`**, with 24.8% of benign emails landing in the $[0.40, 0.50]$ range.
2. **Robust Phishing Signal Generalization:**
   Every one of the 1,500 IWSPA phishing lures was identified with $p \ge 0.9098$, demonstrating that the tokenized URL, credential lure, and urgency features generalized effectively to modern benchmark lures.
3. **Threshold Sensitivity:**
   Because 372 benign samples scored between $0.40$ and $0.4503$, setting an aggressive lower threshold (e.g., $\tau = 0.40$) would have triggered a **24.8% False Positive Rate**. The default threshold $\tau = 0.50$ maintained clean separation.

---

## 7. Operational Limitations & Governance Constraints

> [!CAUTION]
> **Explicit Statement:**  
> **This independent test performance does NOT imply Model 1 can be deployed as an autonomous threat verdict engine.**
> 
> - **BEC Blindness:** Model 1 cannot detect clean conversational Business Email Compromise (BEC) attacks that lack obvious phishing keywords.
> - **Technical Spoofing Blindness:** Model 1 cannot verify cryptographic email signatures (DKIM) or domain sender alignment (SPF/DMARC).
> - **ANVESH Role:** Model 1 serves strictly as a **Tier 1 Statistical Evidence Signal**, which is correlated with Phase 2/3 deterministic forensic pipelines.

---

## 8. Checkpoint Status

- [x] **IWSPA Evaluation Complete:** Documented in `IWSPA_INDEPENDENT_EVALUATION.md` and `iwspa_independent_results.json`.
- [x] **File Integrity Verified:** SHA-256 hashes of `model.joblib` and `independent_test_iwspa.jsonl` are unchanged.
- [x] **ANVESH Challenge Set:** **100% UNTOUCHED (Reserved for Step 5)**.
- [x] **Zero Tuning Performed:** Model 1 parameters remain frozen.

### STOPPED
Awaiting instructions before proceeding to the final ANVESH Challenge Set benchmark.
