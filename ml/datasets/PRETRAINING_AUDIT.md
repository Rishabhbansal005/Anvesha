# ANVESH Phase 4: Pre-Training Dataset & Governance Audit
**Document ID:** `ml/datasets/PRETRAINING_AUDIT.md`  
**Generated:** September 6, 2026  
**Status:** `AUDIT_COMPLETE_AWAITING_TRAINING_APPROVAL`  
**Target Classifier:** Model 1 — Binary Phishing Classifier (`BENIGN` vs `THREAT_PHISHING`)

---

## 1. Executive Summary & Governance Compliance

In compliance with the ANVESH Phase 4 Dataset Governance directives:
1. **Model 1 is strictly a Binary Classifier** (`BENIGN` vs `THREAT_PHISHING`).
2. **`THREAT_ADVANCE_FEE` (419 fraud) is strictly isolated** and excluded from the Model 1 binary training target.
3. **IWSPA-AP Independent Test Set (3,000 samples)** is 100% held-out and completely isolated from development splitting, hyperparameter tuning, and threshold selection.
4. **ANVESH Challenge Benchmark (50 scenarios)** is strictly held-out for final forensic and behavioral evaluation.
5. **Probability Calibration Claims:** Model 1 outputs raw probability estimates (`phishing_probability`, `benign_probability`). No claims of "calibrated probabilities" are made.
6. **Zero Leakage Verified:** Exact SHA-256 duplicate overlap across all partitions is exactly `0`. Normalized text overlap across all boundaries is `0`.

---

## 2. Exact Dataset Counts & Partition Breakdown

| Partition | Total Records | `THREAT_PHISHING` | `BENIGN` | `THREAT_ADVANCE_FEE` | `THREAT_BEC` | Partition Role |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Development: Train** | **6,847** | 3,500 | 2,671 | 676 *(excluded from Model 1 binary fit)* | 0 | 70.0% Development Split |
| **Development: Val** | **2,936** | 1,500 | 1,145 | 291 *(excluded from Model 1 binary fit)* | 0 | 30.0% Development Split |
| **Model 1 Binary Train** | **6,171** | 3,500 | 2,671 | *0 (filtered out)* | 0 | **Active Model 1 Training Set (70.00%)** |
| **Model 1 Binary Val** | **2,645** | 1,500 | 1,145 | *0 (filtered out)* | 0 | **Active Model 1 Validation Set (30.00%)** |
| **Model 1 Binary Dev Total** | **8,816** | 5,000 | 3,816 | *0 (filtered out)* | 0 | **Total Binary Development Corpus** |
| **Advance-Fee Fraud Archive** | **967** | 0 | 0 | 967 | 0 | Retained Related Threat Corpus |
| **IWSPA-AP Independent Test** | **3,000** | 1,500 | 1,500 | 0 | 0 | **100% Isolated Independent Benchmark** |
| **ANVESH Challenge Benchmark** | **50** | 0 | 20 | 0 | 30 | **100% Isolated Forensic Challenge Suite** |
| **Grand Total Unique Samples** | **12,833** | **6,500** | **5,336** | **967** | **30** | Zero Duplication Across Entire Project |

---

## 3. Binary Training Label Definition

Model 1 uses a supervised binary classification scheme:

$$\mathcal{Y} \in \{0, 1\}$$

- **Negative Class ($y = 0$): `BENIGN`**  
  Comprises corporate communications (Enron Corpus) and non-spam mailing list communications (SpamAssassin easy_ham and hard_ham).
- **Positive Class ($y = 1$): `THREAT_PHISHING`**  
  Comprises credential harvesting, lure, and malicious link emails (Mendeley Phishing Dataset, Jose Nazario Phishing Archive).

---

## 4. Original-Label to ANVESH-Label Mapping

Every record preserves both its `original_label` from the source dataset and its normalized `anvesh_label`:

| Source Dataset | `original_label` | `anvesh_label` | Model 1 Binary Role |
| :--- | :--- | :--- | :--- |
| **Mendeley Phishing** | `Phishing Email` | `THREAT_PHISHING` | Included (Positive Class, $y=1$) |
| **Jose Nazario Archive** | `Phishing Email` | `THREAT_PHISHING` | Included (Positive Class, $y=1$) |
| **Jose Nazario Archive** | `advance_fee_fraud` | `THREAT_ADVANCE_FEE` | **EXCLUDED from Model 1 Binary Training** |
| **Enron Corporate** | `corporate_email` | `BENIGN` | Included (Negative Class, $y=0$) |
| **Apache SpamAssassin** | `easy_ham` | `BENIGN` | Included (Negative Class, $y=0$) |
| **Apache SpamAssassin** | `hard_ham` | `BENIGN` | Included (Negative Class, $y=0$) |
| **IWSPA-AP (Held-Out)** | `IWSPA Phishing` | `THREAT_PHISHING` | Held-Out Independent Test ($y=1$) |
| **IWSPA-AP (Held-Out)** | `IWSPA Legitimate` | `BENIGN` | Held-Out Independent Test ($y=0$) |
| **ANVESH Challenge (Held-Out)**| `BEC Scenario` | `THREAT_BEC` | Held-Out Adversarial Benchmark |
| **ANVESH Challenge (Held-Out)**| `Legitimate Scenario` | `BENIGN` | Held-Out False Positive Control |

---

## 5. Treatment of `THREAT_ADVANCE_FEE`

1. **Semantic Separation:** 419 advance-fee fraud emails solicit money or personal details via social engineering narratives but lack modern credential phishing mechanisms or enterprise BEC context.
2. **Exclusion from Model 1:** All 967 `THREAT_ADVANCE_FEE` samples (676 in train split, 291 in val split) are explicitly filtered out during Model 1 binary training and validation fitting.
3. **Preservation:** The records remain intact in the processed JSONL files and provenance ledger with label `THREAT_ADVANCE_FEE`. They are preserved for downstream behavioral/fraud modeling and secondary evaluation.

---

## 6. Duplicate Detection & Cross-Partition Leakage Results

A comprehensive multi-stage audit was executed across all 12,833 samples:

```
=== TOTAL SAMPLES ===
Train total: 6,847 (unique SHA-256 hashes: 6,847)
Val total: 2,936 (unique SHA-256 hashes: 2,936)
Test total: 3,000 (unique SHA-256 hashes: 3,000)
Challenge total: 50 (unique SHA-256 hashes: 50)

=== SHA-256 OVERLAPS (TARGET = 0) ===
Train vs Validation:                 0 (PASSED)
Train vs Independent Test (IWSPA):   0 (PASSED)
Validation vs Independent Test:      0 (PASSED)
Development vs Challenge Set:        0 (PASSED)
Independent Test vs Challenge Set:   0 (PASSED)

=== NORMALIZED TEXT OVERLAPS (TARGET = 0) ===
Train vs Validation:                 0 (PASSED)
Train vs Independent Test:           0 (PASSED)
Validation vs Independent Test:      0 (PASSED)
Development vs Challenge Set:        0 (PASSED)
```

**Deduplication Summary:**
- Raw candidate items processed: 16,050
- Exact SHA-256 duplicates removed: 3,217
- Resulting unique repository samples: 12,833
- Cross-partition contamination rate: **0.000%**

---

## 7. Model 1 Scope & Feature Boundary

Model 1 is strictly constrained to text classification:
$$\text{Input: } (\text{subject}, \text{body}) \xrightarrow{\text{Normalization}} \text{Cleaned Text} \xrightarrow{\text{TF-IDF (1-2 gram)}} \vec{x} \xrightarrow{\text{Logistic Regression}} \hat{y} \in [0, 1]$$

### Explicit Feature Exclusions (Enforced as ANVESH Invariants):
The following features are **STRICTLY EXCLUDED** from Model 1 training and inference:
- SPF / DKIM / DMARC authentication verdicts
- Received header hops & SMTP relay infrastructure
- IP addresses, GeoIP, ASN, ISP, and Cloud hosting tags
- DNS records (MX, SPF, DMARC, NS) & RDAP / WHOIS age
- VirusTotal / AbuseIPDB threat intelligence enrichment scores
- Phase 2/3 Composite Risk Scores and Forensic Dossier outputs

These signals remain independent forensic evidence sources in the ANVESH multi-layered architecture.

---

## 8. Licensing, Provenance & Privacy Status

| Source | Upstream Custodian | License / Terms | Commercial / Academic Use | Privacy / PII Status |
| :--- | :--- | :--- | :--- | :--- |
| **Mendeley Phishing** | Mendeley Data / Univ. | CC BY 4.0 | Permitted with attribution | Stripped of live victim PII |
| **Nazario Archive** | Jose Nazario / Phish.org | Research Public Domain | Permitted for security research | Phishing lures sanitized |
| **Enron Corpus** | FERC / CALO / CMU | Public Domain / Academic | Permitted for research | Corporate data de-indexed |
| **Apache SpamAssassin**| Apache Software Foundation| Apache License 2.0 | Permitted | Public mailing lists |
| **IWSPA-AP Benchmark** | IEEE IWSPA Workshop | IEEE Research / CC BY-NC | Research / Evaluation Only | Sanitized evaluation set |
| **ANVESH Challenge Set**| ANVESH Project Team | Project Proprietary | Internal Forensic Benchmark | Synthetic / Zero Victim PII |

---

## 9. Known Dataset Limitations

1. **Temporal Horizon:** The historical corpora (Enron 2001, Nazario 2005-2007) do not reflect recent 2024-2026 enterprise cloud SaaS impersonation templates (e.g., Okta SSO verify, Microsoft 365 MFA push, DocuSign e-sign lures).
2. **Text-Only Blindness:** A pure text classifier cannot detect a phishing email with clean benign text that embeds a malicious link in an attachment or zero-reputation domain; ANVESH's Phase 2/3 deterministic engine addresses this gap.
3. **No Synthetic Shortcuts:** Synthetic samples have been restricted strictly to the 50-record ANVESH Challenge benchmark to avoid biasing the statistical training distribution.

---

## 10. Confirmation of Strict Isolation

- [x] **IWSPA-AP Independent Test Set:** Verified 100% isolated in `ml/datasets/processed/independent_test_iwspa.jsonl`. Not referenced in any training pipeline or hyperparameter loop.
- [x] **ANVESH Challenge Benchmark:** Verified 100% isolated in `ml/datasets/challenge/anvesh_challenge_50.jsonl`. Reserved exclusively for behavioral/forensic evaluation.
- [x] **Model 1 Target:** Verified binary `BENIGN` vs `THREAT_PHISHING` with `THREAT_ADVANCE_FEE` excluded.
- [x] **Zero Metric Fabrication:** No training metrics or accuracy scores generated prior to actual script execution.

---

## 11. Pre-Training Stop Checkpoint

> [!IMPORTANT]
> **STOP CONDITION REACHED:** Dataset acquisition, cleaning, deduplication, partition isolation, and pre-training governance audit are complete. Model 1 training will NOT begin until this audit report is explicitly reviewed and approved.
