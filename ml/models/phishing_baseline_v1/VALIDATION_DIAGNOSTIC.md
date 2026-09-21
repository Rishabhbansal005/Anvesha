# ANVESH Model 1: Perfect-Validation Diagnostic Audit Report
**Document ID:** `ml/models/phishing_baseline_v1/VALIDATION_DIAGNOSTIC.md`  
**Generated:** September 6, 2026  
**Status:** `DIAGNOSTIC_AUDIT_COMPLETE`  
**Scope:** Development Corpus Only (`train.jsonl` and `val.jsonl`). **IWSPA-AP and ANVESH Challenge Set remain 100% untouched.**

---

## 1. Executive Summary & Core Finding

During baseline evaluation, Model 1 achieved a nominal validation score of:
- **Accuracy:** `1.0000` (100.00%)
- **Precision:** `1.0000` (100.00%)
- **Recall:** `1.0000` (100.00%)
- **F1-Score:** `1.0000` (100.00%)
- **ROC-AUC:** `1.0000`
- **False Positives (FP):** `0`
- **False Negatives (FN):** `0`

### Primary Forensic Conclusion
> [!CAUTION]
> **This 100% validation score is NOT evidence of a flawless real-world phishing detector.**  
> It is the direct consequence of **Source-Label Confounding** inherent in classical historical email research corpora (e.g. Enron Corporate emails vs. Mendeley/Nazario phishing lures). Because each constituent dataset in the development corpus is mono-labeled, the standard stratified random split evaluates in-distribution vocabulary that is trivially separable by TF-IDF and Logistic Regression.

---

## 2. Source Distribution & Label Confounding Audit

| Source Dataset | Development Train | Development Val | Total Benign | Total Phishing | Label Purity | Primary Content Domain |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **`enron_corporate_corpus`** | 2,381 | 1,028 | 3,409 | 0 | **100% BENIGN** | 2001 Energy trading, FERC regulatory, pipelines |
| **`spamassassin_public_corpus`** | 290 | 117 | 407 | 0 | **100% BENIGN** | Linux/open-source mailing lists, tech discussion |
| **`mendeley_nazario_phishing_corpus`** | 3,500 | 1,500 | 0 | 5,000 | **100% PHISHING** | Credential harvesting, bank/eBay/DocuSign lures |
| **Total Binary Development** | **6,171** | **2,645** | **3,816** | **5,000** | — | — |

### Finding: Complete Source Correlation
- Every benign sample in the development corpus originates from either Enron (89.3%) or SpamAssassin (10.7%).
- Every phishing sample originates from Mendeley / Jose Nazario (100.0%).
- Because train and validation splits were drawn randomly from this combined corpus, the validation set tests the classifier on the exact same corporate and lure distributions present during training.

---

## 3. Classification Score & Probability Distribution Audit

Evaluating the 2,645 validation samples under the fitted baseline model reveals an extreme bimodal polarization:

- **Overall Probability Range:** Minimum = `0.0048`, Maximum = `0.9965`, Median = `0.9844`
- **Benign Subset (1,145 samples):**
  - Minimum Phishing Probability: `0.0048`
  - Maximum Phishing Probability: `0.0543`
  - Median Phishing Probability: `0.0126`
  - Mean Phishing Probability: `0.0142`
- **Phishing Subset (1,500 samples):**
  - Minimum Phishing Probability: `0.9827`
  - Maximum Phishing Probability: `0.9965`
  - Median Phishing Probability: `0.9863`
  - Mean Phishing Probability: `0.9884`

### Histogram of Predicted Phishing Probabilities (Validation Set)

| Probability Bin | Actual BENIGN Count | Actual PHISHING Count | Total Samples |
| :---: | :---: | :---: | :---: |
| **0.00 – 0.10** | **1,145** (100%) | 0 (0%) | 1,145 |
| **0.10 – 0.20** | 0 | 0 | 0 |
| **0.20 – 0.30** | 0 | 0 | 0 |
| **0.30 – 0.40** | 0 | 0 | 0 |
| **0.40 – 0.50** | 0 | 0 | 0 |
| **0.50 – 0.60** | 0 | 0 | 0 |
| **0.60 – 0.70** | 0 | 0 | 0 |
| **0.70 – 0.80** | 0 | 0 | 0 |
| **0.80 – 0.90** | 0 | 0 | 0 |
| **0.90 – 1.00** | 0 | **1,500** (100%) | 1,500 |

- **Samples near decision boundary $[0.40, 0.60]$:** **`0`**
- **Observation:** There are zero borderline cases on the in-distribution validation split. The classifier easily separates Enron energy jargon from credential phishing tokens.

---

## 4. Feature Inspection & Vocabulary Artifacts

### Top 30 Positive Features (`THREAT_PHISHING`)
These capture legitimate phishing lure patterns, urgency terms, and tokenized URLs:
1. `__url_token__` (+2.8468)
2. `your` (+2.1954)
3. `__url_token__ to` (+1.9430)
4. `at __url_token__` (+1.7435)
5. `transfer` (+1.7114)
6. `access` (+1.6301)
7. `to` (+1.6154)
8. `payment` (+1.5841)
9. `invoice` (+1.5841)
10. `you` (+1.5827)
11. `document` (+1.5732)
12. `verification` (+1.4777)
13. `has` (+1.3928)
14. `click` (+1.3614)
15. `of __currency_token__` (+1.3574)
16. `queued` (+1.3365)
17. `view` (+1.3263)
18. `__email_token__` (+1.2600)
19. `__currency_token__` (+1.2493)
20. `account` (+1.2337)
21. `direct deposit` (+1.2174)
22. `deposit` (+1.2174)
23. `direct` (+1.2174)
24. `notice` (+1.2050)
25. `shared` (+1.1518)
26. `been` (+1.1086)
27. `has been` (+1.1086)
28. `docusign` (+1.1019)
29. `at` (+1.0994)
30. `sign` (+1.0801)

### Top 30 Negative Features (`BENIGN`)
These are heavily dominated by Enron-specific corporate energy artifacts:
1. `the` (-2.3498)
2. `please` (-1.5262)
3. `be` (-1.3049)
4. `2001` (-1.2787) *(Enron year artifact)*
5. `august` (-1.2787) *(Enron month artifact)*
6. `delivery` (-1.2646)
7. `attached` (-1.2107)
8. `for the` (-1.1957)
9. `is the` (-1.1410)
10. `engineering` (-1.1172)
11. `expansion` (-1.1172)
12. `review` (-1.0935)
13. `we` (-1.0868)
14. `budget` (-1.0779)
15. `we have` (-1.0769)
16. `gas` (-1.0311) *(Enron energy sector)*
17. `filing` (-1.0068) *(Enron regulatory)*
18. `ferc` (-1.0068) *(Federal Energy Regulatory Commission)*
19. `regulatory` (-1.0068) *(Enron regulatory)*
20. `scheduled` (-0.9901)
21. `compressor` (-0.9901) *(Enron pipeline equipment)*
22. `station` (-0.9901)
23. `maintenance` (-0.9901)
24. `outage` (-0.9901)
25. `compressor station` (-0.9901)
26. `trading` (-0.9813) *(Enron energy trading)*
27. `agreement` (-0.9791)
28. `capital` (-0.9766)
29. `will be` (-0.9694)
30. `capacity` (-0.9433)

**Diagnostic Insight:** The negative weights show that the model heavily relies on Enron-specific terminology (`ferc`, `compressor station`, `gas`, `2001`) to confirm benign status. When a modern business email does not contain these Enron artifacts, its benign classification confidence will be noticeably lower.

---

## 5. Diagnostic Source-Holdout Experiment

To test out-of-source generalization **without touching IWSPA-AP**, a diagnostic source-holdout experiment was conducted on the development corpus:

- **Training Partition:** `enron_corporate_corpus` (3,409 benign) + 70% of `mendeley_nazario_phishing_corpus` (3,500 phishing).
- **Held-Out Test Partition:** `spamassassin_public_corpus` (407 benign) + 30% of `mendeley_nazario_phishing_corpus` (1,500 phishing).

### Diagnostic Holdout Results:
- **Total Test Samples:** 1,907
- **Accuracy:** `0.9995`
- **Precision:** `0.9993`
- **Recall:** `1.0000`
- **F1-Score:** `0.9997`
- **Confusion Matrix:** TP=1,500, TN=406, FP=1, FN=0
- **False Positive Rate on Out-of-Source Benign (SpamAssassin):** `1 / 407` (0.25%)
- **SpamAssassin Probability Shift:**
  - Minimum Phishing Probability: `0.2965`
  - Maximum Phishing Probability: `0.6234`
  - **Median Phishing Probability: `0.4414`** (Mean: `0.4234`)

### Critical Diagnostic Finding:
When benign emails lack Enron domain vocabulary (as with SpamAssassin mailing list emails), the predicted phishing probability shifts from $\approx 0.012$ up to a median of **`0.4414`**, directly adjacent to the 0.50 decision boundary. This confirms that:
1. The 100% in-distribution validation score is heavily driven by Enron corporate vocabulary familiarity.
2. Out-of-source benign emails will experience significant probability drift.

---

## 6. Preprocessing & Data Pipeline Integrity Audit

The input pipeline was audited to ensure zero data leakage or label contamination:
- [x] **Input Content:** Strictly `subject` + `body`.
- [x] **No Labels or Metadata in Text:** `anvesh_label`, `original_label`, `source_dataset`, and `file_path` are strictly excluded from text fields.
- [x] **No Verdict/Risk Engine Bleed:** Risk scores, threat intelligence results, and forensic dossier fields are not accessible to Model 1.
- [x] **No Header Leakage:** Authentication headers (`Authentication-Results`, `Received`, `DKIM-Signature`, `SPF`) are stripped during ingestion and cannot enter Model 1.
- [x] **Identical Preprocessing:** Training, validation, and inference all execute the exact same `normalize_email_pair(subject, body)` function from `ml/preprocessing/text_cleaner.py`.

---

## 7. Baseline Integrity Confirmation

The trained Model 1 pipeline was verified against required specifications:
- `TfidfVectorizer(ngram_range=(1, 2), max_features=10000, sublinear_tf=True, token_pattern='(?u)\\b\\w+\\b|__\\w+__')`
- `LogisticRegression(C=1.0, class_weight='balanced', random_state=42, max_iter=1000, solver='lbfgs')`
- No hyperparameter tuning or feature removal was performed.

---

## 8. Final Conclusion & Recommendation

1. **Why Model 1 Scored 100% on Validation:**  
   The development corpus combines two very distinct historical datasets: Enron energy trading corporate memos (2001) and credential phishing attacks (2005–2020). In a random train/val split, TF-IDF easily learns distinct non-overlapping vocabulary clusters.
2. **What to Expect on IWSPA-AP:**  
   When Model 1 is eventually evaluated on the 100% held-out **IWSPA-AP Independent Test Set**, accuracy will naturally normalize to realistic out-of-distribution levels (e.g. ~85–95%) because IWSPA contains contemporary non-Enron benign emails and modern phishing lures.
3. **Architecture Validation:**  
   This diagnostic proves precisely why ANVESH's multi-layered architecture is necessary: text classification alone cannot reliably establish email safety, and must be combined with deterministic authentication (SPF/DKIM/DMARC), infrastructure reputation, and behavioral BEC signals.

---

## 9. Checkpoint Status

> [!IMPORTANT]
> **DIAGNOSTIC AUDIT COMPLETE.**  
> - IWSPA-AP Independent Test Set (`independent_test_iwspa.jsonl`) remains **100% untouched**.  
> - ANVESH Challenge Set (`anvesh_challenge_50.jsonl`) remains **100% untouched**.  
> - Phase 2 and Phase 3 pipelines remain fully operational (21/21 backend tests passing).  
> - No model tuning or parameter changes have been made.
