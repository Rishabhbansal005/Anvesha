# ANVESH Source-Aware Evaluation Report
**Document ID:** `ml/evaluation/SOURCE_AWARE_EVALUATION.md`  
**Generated:** September 6, 2026  
**Status:** `EVALUATION_METHODOLOGY_COMPLETE`  
**Scope:** Development Corpus Only (`train.jsonl` + `val.jsonl`).  
**Governance Invariant:** **IWSPA-AP Independent Test Set and ANVESH Challenge Set remain 100% untouched.**

---

## 1. Executive Summary & Core Methodology Insight

Standard machine learning practice often relies on random stratified splits (e.g., 70% train / 30% val). However, in email security datasets where constituent corpora are **100% mono-labeled**, random splitting evaluates in-distribution lexical memorization rather than true semantic generalization.

To rigorously quantify this vulnerability **prior to touching any held-out benchmark**, we established a source-aware evaluation pipeline across the 8,816 binary development records:
- **`enron_corporate_corpus`**: 3,409 records (100% `BENIGN`)
- **`spamassassin_public_corpus`**: 407 records (100% `BENIGN`)
- **`mendeley_nazario_phishing_corpus`**: 5,000 records (100% `THREAT_PHISHING`)

---

## 2. Source-Label Confounding Explained

### What is Source-Label Confounding?
Source-label confounding occurs when an extraneous metadata variable (in this case, `source_dataset`) has a 1.0 correlation with the ground-truth label $\mathcal{Y}$. 

$$\mathcal{P}(\mathcal{Y} = \text{PHISHING} \mid \text{Source} = \text{Mendeley/Nazario}) = 1.00$$
$$\mathcal{P}(\mathcal{Y} = \text{BENIGN} \mid \text{Source} = \text{Enron}) = 1.00$$

When a statistical text classifier (TF-IDF + Logistic Regression) trains on a merged multi-source corpus with a random train/val split:
1. The model does not need to learn invariant characteristics of phishing lures vs. legitimate emails.
2. Instead, it trivially learns that 2001 Enron energy-sector vocabulary (`ferc`, `gas`, `pipeline`, `trading`, `compressor station`) indicates `BENIGN`.
3. In-distribution validation achieves a deceptive **100.00% accuracy** because the validation split contains identical Enron-specific jargon.

---

## 3. Experimental Setup & Comparative Results

We conducted three controlled source-aware experiments using the exact production architecture (`TfidfVectorizer(ngram_range=(1,2), max_features=10000, sublinear_tf=True)` + `LogisticRegression(C=1.0, class_weight='balanced', random_state=42)`):

### Overview Table: Experiments A, B, and C

| Experiment | Training Composition | Evaluation Composition | Evaluation Accuracy | Phishing Precision | Phishing Recall | Benign FPR | Phishing FNR | Median Benign Proba |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Experiment A** | Enron (3,409) + 70% Phish (3,500) | SpamAssassin (407) + 30% Phish (1,500) | **0.9995** | 0.9993 | 1.0000 | **0.25%** (1/407) | 0.00% | **0.4414** *(Near boundary)* |
| **Experiment B** | SpamAssassin (407) + 70% Phish (3,500) | Enron (3,409) + 30% Phish (1,500) | **0.3056** | 0.3056 | 1.0000 | **100.00%** (3,409/3,409) | 0.00% | **0.9250** *(Catastrophic collapse)* |
| **Experiment C** | Mixed Enron+SA (6,170) + 70% Phish | Mixed Enron+SA (1,146) + 30% Phish | **1.0000** | 1.0000 | 1.0000 | **0.00%** (0/1,146) | 0.00% | **0.0131** *(In-distribution)* |

---

## 4. In-Depth Experiment Breakdown

### Experiment A: Large Corporate $\rightarrow$ Small Technical Mailing List
- **Train**: Enron Corporate (3,409 benign) + 3,500 phishing.
- **Eval**: SpamAssassin Public (407 benign) + 1,500 phishing.
- **Confusion Matrix**: TP = 1,500, TN = 406, FP = 1, FN = 0.
- **Probability Distribution on SpamAssassin Benign**:
  - Minimum Phishing Proba: `0.2965`
  - Maximum Phishing Proba: `0.6234`
  - **Median Phishing Proba: `0.4414`** (Mean: `0.4234`)
  - Samples in $[0.40, 0.60]$ decision boundary: **332 / 407 (81.6%)**
- **Observation**: Although top-line accuracy is high (99.95%), the model's confidence on out-of-source benign emails dropped precipitously from $0.01$ down to $0.44$, hovering right on the edge of misclassification.

---

### Experiment B: Small Technical Mailing List $\rightarrow$ Large Corporate (Catastrophic Collapse)
- **Train**: SpamAssassin (407 benign) + 3,500 phishing.
- **Eval**: Enron Corporate (3,409 benign) + 1,500 phishing.
- **Confusion Matrix**: TP = 1,500, TN = 0, FP = 3,409, FN = 0.
- **Accuracy**: **`0.3056`** (Collapsed to base phishing prevalence rate $\frac{1500}{4909}$).
- **Enron Benign False Positive Rate**: **`100.00%`** (All 3,409 corporate emails misclassified as phishing).
- **Enron Predicted Phishing Probability**:
  - Minimum: `0.7955`
  - Maximum: `0.9604`
  - **Median: `0.9250`** (Mean: `0.9235`)
- **Root Cause**: Because the model only saw Linux developer mailing list text as benign, ordinary corporate memos, meeting agendas, and formal English triggered positive phishing weights or default bias, classifying every corporate email as malicious with $>92\%$ confidence.

---

### Experiment C: Standard Mixed Development Split
- **Train**: 70% Enron (2,386) + 70% SpamAssassin (284) + 70% Phishing (3,500).
- **Eval**: 30% Enron (1,023) + 30% SpamAssassin (123) + 30% Phishing (1,500).
- **Confusion Matrix**: TP = 1,500, TN = 1,146, FP = 0, FN = 0.
- **Accuracy**: `1.0000` (100.00%).
- **Enron Sub-Val Median Proba**: `0.0134`.
- **SpamAssassin Sub-Val Median Proba**: `0.0111`.
- **Observation**: When both sources are present in training, the model achieves artificial perfection on both validation subsets because both lexicons are memorized during training.

---

## 5. Key Forensic Conclusions & Reliability Assessment

### Is Model 1 Reliable for Autonomous Real-World Deployment?
> [!CAUTION]
> **NO.** Model 1 (pure TF-IDF + Logistic Regression) is **NOT reliable as a standalone decision maker.**  
> Experiment B conclusively proves that a pure text classifier trained on narrow benign distributions will catastrophically misclassify out-of-distribution corporate communications. 

### Why ANVESH's Multi-Layered Architecture is Essential:
1. **Deterministic Layer Grounding**: Technical authentication (SPF/DKIM/DMARC PASS from a verified corporate domain) prevents false positives on clean corporate emails even when text classifiers exhibit out-of-distribution drift.
2. **Infrastructure Evidence**: Real domain age (RDAP), MX reputation, and IP intelligence isolate malicious infrastructure independently of email wording.
3. **Behavioral BEC Rules**: Target impersonation and bank account change patterns are verified against historical communication baselines rather than pure n-gram frequencies.

---

## 6. Limitations of this Evaluation
1. The development corpus contains only two historical benign sources (Enron 2001 and SpamAssassin 2002).
2. The phishing corpus (Mendeley/Nazario) contains historical lures that may not reflect contemporary cloud SaaS impersonations.
3. Final out-of-source generalization benchmark will be established on the **IWSPA-AP Independent Test Set**.

---

## 7. Governance Verification Ledger

| Governance Requirement | Verification Status |
| :--- | :--- |
| **`independent_test_iwspa.jsonl` Untouched** | **VERIFIED (0 bytes read/evaluated)** |
| **`anvesh_challenge_50.jsonl` Untouched** | **VERIFIED (0 bytes read/evaluated)** |
| **`model.joblib` Preserved** | **VERIFIED (Production artifact unchanged)** |
| **Hyperparameters Unaltered** | **VERIFIED (Standard C=1.0, balanced weights)** |
| **Phase 2 & Phase 3 Intact** | **VERIFIED (21/21 backend tests passing)** |
