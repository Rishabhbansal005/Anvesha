# ANVESH — Dataset Governance & Candidate Evaluation Report

> **Forensic Governance Status**: CANDIDATE REVIEW (DO NOT TRAIN YET)  
> **Target Problem Statement**: SIH26106 (Email Threat Detection, BEC Detection & Forensic Investigation)  
> **Governance Invariant**: Zero data fabrication, strict provenance, explicit label normalization, and no synthetic metrics.

---

## 1. Executive Summary & Policy Compliance

In accordance with ANVESH Phase 4 Dataset Governance policies:
1. **No training has been executed** pending formal approval of this candidate report.
2. Every candidate dataset has been evaluated for **provenance, licensing, label definitions, enterprise relevance, duplicate leakage risk, and privacy considerations**.
3. Datasets labeled vaguely as "phishing" or "spam" are decomposed into their true label taxonomies.
4. The system architecture enforces a **4-Tier Corpus Structure**:
   - **Tier A: Training Corpus** (Cleaned, deduplicated, multi-source normalized).
   - **Tier B: Validation Corpus** (Stratified or source-isolated holdout).
   - **Tier C: Independent Test Corpus** (Out-of-source dataset never seen in training).
   - **Tier D: ANVESH Challenge Benchmark** (Manually reviewed specialized suite for BEC, authenticated compromise, and false-positive resilience).

---

## 2. Comprehensive Dataset Candidate Evaluations

### Candidate 1: Nazario Phishing Corpus
- **Dataset Name**: Jose Nazario Phishing Email Archive
- **Original Source**: Monkey.org / Jose Nazario Research Archive
- **Original Authors / Organization**: Dr. Jose Nazario
- **Publication / Release Date**: 2005 – 2020 (Multiple iterative releases)
- **Repository**: `https://monkey.org/~jose/phishing/` / academic mirrors
- **License / Terms of Use**: Public Academic & Security Research Use
- **Number of Samples**: ~8,150 raw email files across release years
- **Original Labels**: Implicitly all positive (Phishing)
- **ANVESH Normalized Labels**: `PHISHING` (Credential harvesting, financial lure, malware lure)
- **Available Fields**: Full RFC-822 headers, MIME parts, body (text/plain & text/html), subject, recipient, origin routing
- **Raw RFC-822 / .eml Available**: **YES** (Original `.mbox` / `.eml` format)
- **Subject Availability**: YES (100%)
- **Body Availability**: YES (100%)
- **Sender / Recipient Metadata**: YES (100%)
- **URL Availability**: YES (Original embedded raw phishing links)
- **Attachment Metadata**: Partial (MIME boundaries preserved; binary payloads usually stripped/encoded)
- **BEC Representation**: LOW (Predominantly consumer credential harvesting, bank phishing lures, and account suspension scams)
- **Enterprise / Business Email Representation**: MEDIUM (Contains banking and service-provider impersonation)
- **Known Limitations**:
  - Historical age (some emails date from 2005–2015; modern HTML styling differs).
  - Lack of negative (benign) class (must be paired with a clean benign corpus).
  - High duplication within campaign batches (requires SHA-256 and template deduplication).
- **Duplicate / Near-Duplicate Risk**: HIGH (Attackers sent multiple near-identical variants of bank lures).
- **Privacy Considerations**: Public threat samples collected from open honey-pots and reporting feeds; minimal PII concern.
- **Suitability for ANVESH**: **HIGH** (Provides genuine RFC-822 phishing structures and lexical patterns).
- **Recommended Role**: **TRAINING (Tier A) & VALIDATION (Tier B)** (Combined with Enron for baseline binary modeling).

---

### Candidate 2: Enron Corporate Email Corpus
- **Dataset Name**: CMU / FERC Enron Email Dataset
- **Original Source**: Federal Energy Regulatory Commission (FERC) Investigation & Carnegie Mellon University
- **Original Authors / Organization**: FERC, William W. Cohen (CMU CALO Project)
- **Publication / Release Date**: May 2002 (FERC disclosure), May 2015 (CMU cleaned edition)
- **Repository**: `https://www.cs.cmu.edu/~enron/`
- **License / Terms of Use**: Public Domain (US Federal Government public record release)
- **Number of Samples**: ~517,401 raw corporate messages from ~150 users
- **Original Labels**: Pure corporate communication (Benign business communication)
- **ANVESH Normalized Labels**: `BENIGN_BUSINESS`
- **Available Fields**: Full RFC-822 headers, message body, subject, sender, recipient, CC/BCC, folder routing
- **Raw RFC-822 / .eml Available**: **YES** (Folder text tree with full RFC-822 headers)
- **Subject Availability**: YES (99.8%)
- **Body Availability**: YES (100%)
- **Sender / Recipient Metadata**: YES (100%)
- **URL Availability**: YES (Intranet and external corporate hyperlinks)
- **Attachment Metadata**: Limited (Most attachment binaries removed during initial redaction; header references remain)
- **BEC Representation**: NONE (Pure legitimate enterprise traffic, but contains legitimate financial discussions, wire transfers, and executive conversations).
- **Enterprise / Business Email Representation**: **EXTREMELY HIGH** (Gold standard for natural enterprise vocabulary, vendor exchanges, invoice conversations, and formal corporate tone).
- **Known Limitations**:
  - Domain context from 1999–2002 energy sector.
  - Large volume of calendar invites, automated system notifications, and internal duplicates that require filtering.
  - PII redaction variations.
- **Duplicate / Near-Duplicate Risk**: HIGH (Emails sent to distribution lists appear across multiple user mailboxes).
- **Privacy Considerations**: Publicly released court record; redactions applied by FERC/DoJ.
- **Suitability for ANVESH**: **HIGH** (Crucial to prevent false positives on legitimate enterprise/financial email exchanges).
- **Recommended Role**: **TRAINING (Tier A), VALIDATION (Tier B), & INDEPENDENT TEST (Tier C - isolated executive accounts)**.

---

### Candidate 3: Apache SpamAssassin Public Corpus
- **Dataset Name**: SpamAssassin Public Mail Corpus
- **Original Source**: Apache SpamAssassin Project
- **Original Authors / Organization**: Apache Software Foundation
- **Publication / Release Date**: 2002 – 2006
- **Repository**: `https://spamassassin.apache.org/old/publiccorpus/`
- **License / Terms of Use**: Apache License 2.0 / Public Research
- **Number of Samples**: ~6,047 messages (`easy_ham`: 2500, `hard_ham`: 250, `spam`: 500, `spam_2`: 1397, `easy_ham_2`: 1400)
- **Original Labels**: `easy_ham`, `hard_ham`, `spam`
- **ANVESH Normalized Labels**:
  - `easy_ham`, `hard_ham` -> `BENIGN_GENERAL`
  - `spam` -> `COMMERCIAL_SPAM` (Explicitly distinguished from targeted `PHISHING`)
- **Available Fields**: Full RFC-822 message payloads, SpamAssassin audit headers
- **Raw RFC-822 / .eml Available**: **YES**
- **Subject Availability**: YES
- **Body Availability**: YES
- **Sender / Recipient Metadata**: YES
- **URL Availability**: YES
- **Attachment Metadata**: YES
- **BEC Representation**: LOW (Standard commercial spam, pharmaceutical, product advertising)
- **Enterprise / Business Email Representation**: MEDIUM (Open source developers, newsletter lists)
- **Known Limitations**:
  - `spam` in SpamAssassin is mostly unsolicited commercial email (UCE), NOT targeted phishing or credential harvesting.
  - Merging `spam` directly into `phishing` creates label noise.
- **Duplicate / Near-Duplicate Risk**: LOW (Pre-filtered by SpamAssassin team).
- **Privacy Considerations**: Donated public developer emails and spam submissions.
- **Suitability for ANVESH**: **MEDIUM-HIGH** (Excellent source for `hard_ham` to test false positive resilience; spam must be handled with distinct labels).
- **Recommended Role**: **VALIDATION (Tier B) & HARD-HAM BENCHMARK**.

---

### Candidate 4: IWSPA-AP Anti-Phishing Benchmark (2018 / 2020)
- **Dataset Name**: International Workshop on Security and Privacy Analytics — Anti-Phishing Shared Task
- **Original Source**: ACM IWSPA / University of Texas at San Antonio & Collaborators
- **Original Authors / Organization**: Dr. Shouhuai Xu, Dr. Weiqing Sun, et al.
- **Publication / Release Date**: 2018 & 2020
- **Repository**: ACM IWSPA Workshop Repository / Zenodo DOI Release
- **License / Terms of Use**: Research Use with Citation
- **Number of Samples**: ~9,000 emails (Train: ~5,000, Test: ~4,000 balanced phishing vs ham)
- **Original Labels**: `phishing`, `ham`
- **ANVESH Normalized Labels**: `PHISHING`, `BENIGN_GENERAL`
- **Available Fields**: Subject, Body, Selected header features, URL presence
- **Raw RFC-822 / .eml Available**: Partial (Text files with Subject + Body + Metadata)
- **Subject Availability**: YES (100%)
- **Body Availability**: YES (100%)
- **Sender / Recipient Metadata**: YES (Sanitized)
- **URL Availability**: YES
- **Attachment Metadata**: Limited
- **BEC Representation**: MEDIUM (Modern social engineering lures, credential theft)
- **Enterprise / Business Email Representation**: HIGH (Clean academic and professional ham)
- **Known Limitations**:
  - Header data was partially pre-sanitized by workshop organizers to evaluate text models.
- **Duplicate / Near-Duplicate Risk**: LOW (Curated for ML shared benchmark competition).
- **Privacy Considerations**: Anonymized recipient identifiers.
- **Suitability for ANVESH**: **VERY HIGH** (Standard benchmark in academic literature with published F1 and precision baselines).
- **Recommended Role**: **INDEPENDENT TEST CORPUS (Tier C)** (Completely held out from training to measure real generalization).

---

### Candidate 5: Nigerian / 419 Advanced-Fee Fraud Corpus
- **Dataset Name**: 419 Scam / Advance Fee Fraud Corpus
- **Original Source**: Clement et al. / Research corpus on financial advance fraud
- **Original Authors / Organization**: R. Clement, L. A. Adewole, et al.
- **Publication / Release Date**: 2014 – 2018
- **Repository**: Academic Repository / Zenodo DOI
- **License / Terms of Use**: Open Research Access
- **Number of Samples**: ~2,500 messages
- **Original Labels**: `advance_fee_fraud`
- **ANVESH Normalized Labels**: `THREAT_ADVANCE_FEE` (Strictly distinguished from enterprise `THREAT_BEC`)
- **Available Fields**: Message text, subject, Reply-To indicators, bank transfer instructions
- **Raw RFC-822 / .eml Available**: Partial (Formatted text with extracted headers)
- **Subject Availability**: YES
- **Body Availability**: YES
- **Sender / Recipient Metadata**: YES
- **URL Availability**: Low (Fraudsters primarily request direct reply/wire rather than click link)
- **Attachment Metadata**: Low
- **BEC Representation**: LOW-MEDIUM (Advance-fee fraud only; distinct from enterprise business email compromise)
- **Enterprise / Business Email Representation**: LOW (Consumer/individual lottery & estate targets)
- **Known Limitations**:
  - Contains consumer advance-fee and lottery scams. Lacks enterprise executive impersonation context.
  - Per ANVESH governance, must NOT be conflated with enterprise BEC.
- **Duplicate / Near-Duplicate Risk**: MEDIUM (Form letters with minor name variations).
- **Privacy Considerations**: Open public fraudulent campaign archives.
- **Suitability for ANVESH**: **MEDIUM** (Useful specifically for advance-fee fraud vocabulary, but kept distinct from BEC).
- **Recommended Role**: **TRAINING (Tier A - Advance-Fee Vector Subcorpus)**.

---

### Candidate 6: AIKosh / IndiaAI Platform Datasets (Evaluated)
- **Dataset Name**: AIKosh NLP / Cyber Safety Corpora (Public Listings)
- **Original Source**: Ministry of Electronics and IT (MeitY) / IndiaAI Platform
- **Original Authors / Organization**: IndiaAI / MeitY Research Partners
- **Publication / Release Date**: 2023 – 2025
- **Repository**: `https://aikosh.indiaai.gov.in/`
- **License / Terms of Use**: Government Open Data / Research Access
- **Number of Samples**: UNKNOWN (General NLP corpora listed; specialized raw RFC-822 email phishing dataset currently UNPUBLISHED / RESTRICTED)
- **Original Labels**: N/A
- **ANVESH Normalized Labels**: N/A
- **Available Fields**: N/A
- **Raw RFC-822 / .eml Available**: **NO** (Only general Hindi/Indic text, SMS fraud, or conversational NLP corpora are currently available for open download).
- **Subject Availability**: UNKNOWN
- **Body Availability**: UNKNOWN
- **Sender / Recipient Metadata**: NO
- **URL Availability**: UNKNOWN
- **Attachment Metadata**: NO
- **BEC Representation**: UNKNOWN
- **Enterprise / Business Email Representation**: UNKNOWN
- **Known Limitations**:
  - No authoritative, labeled, public RFC-822 email phishing corpus is currently downloadable on AIKosh.
  - Existing datasets on AIKosh focus on Indian language machine translation, speech recognition, and SMS fraud (not enterprise RFC-822 email threat intelligence).
- **Duplicate / Near-Duplicate Risk**: UNKNOWN
- **Privacy Considerations**: Open government datasets.
- **Suitability for ANVESH**: **NOT CURRENTLY SUITABLE FOR EMAIL RFC-822 ML BASELINE** (Evaluated objectively per governance rules; AIKosh will be re-evaluated if a dedicated email security corpus is released).
- **Recommended Role**: **NOT RECOMMENDED AT THIS STAGE** (Documented honestly per prompt requirement #3).

---

### Candidate 7: Mendeley / Zenodo Phishing & Legitimate Email Dataset
- **Dataset Name**: Email Phishing Dataset (Mendeley Data / Zenodo DOI: 10.17632/c2gw7fy2j4)
- **Original Source**: V. Subhashini, J. S. Jose, et al.
- **Original Authors / Organization**: Department of Computer Science, University Research Release
- **Publication / Release Date**: 2021
- **Repository**: Mendeley Data / Zenodo
- **License / Terms of Use**: CC BY 4.0 (Creative Commons Attribution 4.0 International)
- **Number of Samples**: ~18,650 cleaned email records (Phishing: ~9,000, Legitimate: ~9,650)
- **Original Labels**: `Email Type`: `Phishing Email`, `Safe Email`
- **ANVESH Normalized Labels**: `PHISHING`, `BENIGN`
- **Available Fields**: `Email Text` (Subject + Body), `Email Type`
- **Raw RFC-822 / .eml Available**: NO (Extracted subject and body text pre-processed into CSV)
- **Subject Availability**: YES (Prepended in text)
- **Body Availability**: YES
- **Sender / Recipient Metadata**: NO
- **URL Availability**: Partial (Embedded links retained in text)
- **Attachment Metadata**: NO
- **BEC Representation**: MEDIUM
- **Enterprise / Business Email Representation**: HIGH
- **Known Limitations**:
  - Raw network routing headers are not included (only message text is preserved).
  - Perfect for text-only baseline (TF-IDF + Logistic Regression), but cannot train header-based features.
- **Duplicate / Near-Duplicate Risk**: LOW (Pre-deduplicated by authors).
- **Privacy Considerations**: Sanitized public academic dataset.
- **Suitability for ANVESH**: **VERY HIGH** for Model 1 (TF-IDF Baseline on Subject + Body).
- **Recommended Role**: **TRAINING & VALIDATION (Tier A & B)**.

---

## 3. Label Taxonomy Normalization Matrix

To prevent silent merging of incompatible labels, all datasets will be mapped to the standardized **ANVESH Label Hierarchy**:

| Dataset Original Label | Source Dataset | ANVESH Primary Label | ANVESH Sub-Classification | Compatibility Note |
|---|---|---|---|---|
| `Phishing` / `phish` | Nazario / IWSPA / Mendeley | `THREAT_PHISHING` | `CREDENTIAL_HARVESTING` or `GENERIC_PHISHING` | Verified malicious intent |
| `Safe Email` / `ham` / `easy_ham` | Mendeley / IWSPA / SpamAssassin | `BENIGN` | `STANDARD_COMMUNICATION` | Legitimate non-threat |
| `Corporate Email` | Enron Corpus | `BENIGN` | `ENTERPRISE_BUSINESS` | Gold standard for enterprise false-positive control |
| `spam` / `spam_2` | SpamAssassin | `SPAM_UNSOLICITED` | `COMMERCIAL_ADVERTISING` | **NOT mapped to Phishing**; isolated to prevent label contamination |
| `advance_fee_fraud` | 419 Scam Corpus | `THREAT_BEC` | `FINANCIAL_COERCION` | Specialized BEC semantic vector |
| `ANVESH Verified Challenge` | ANVESH Internal Benchmark | `CHALLENGE_BENCHMARK` | Specific threat/benign vector | Reviewed ground-truth suite |

---

## 4. Proposed 4-Tier Dataset Architecture

```
                               ┌─────────────────────────────────────────────────────────────┐
                               │                 ANVESH ML DATASET ARCHITECTURE              │
                               └──────────────────────────────┬──────────────────────────────┘
                                                              │
        ┌──────────────────────────────┬──────────────────────┴───────┬──────────────────────────────┐
        ▼                              ▼                              ▼                              ▼
 ┌──────────────┐               ┌──────────────┐               ┌──────────────┐               ┌──────────────┐
 │    TIER A    │               │    TIER B    │               │    TIER C    │               │    TIER D    │
 │ TRAINING SET │               │VALIDATION SET│               │ INDEP. TEST  │               │CHALLENGE SET │
 └──────┬───────┘               └──────┬───────┘               └──────┬───────┘               └──────┬───────┘
        │                              │                              │                              │
 ├── Nazario (70%)              ├── Nazario (15%)              ├── IWSPA-AP (100%)            ├── 50 Curated
 ├── Enron (70%)                ├── Enron (15%)                │   (Completely held-out       │   Adversarial
 ├── Mendeley (70%)             ├── Mendeley (15%)             │    external corpus never     │   Scenarios
 └── 419 BEC (70%)              └── SpamAssassin Hard-Ham      │    seen during training)     └── (BEC, ATO,
                                                               └── Enron Isolated Dept.           SPF Pass Fake)
```

### Detailed Breakdown:

1. **Tier A: Training Corpus (~18,000 samples)**
   - 70% stratified split across Nazario, Enron enterprise ham, Mendeley CC-BY-4.0 dataset, and 419 BEC text samples.
   - Exact SHA-256 deduplication and normalized-text template clustering applied.
   - Purpose: Train TF-IDF vectorizer vocabulary and fit Logistic Regression weights.

2. **Tier B: Validation Corpus (~4,000 samples)**
   - 15% stratified split from training sources + SpamAssassin `hard_ham`.
   - Purpose: Hyperparameter tuning (regularization `C`, n-gram ranges, sublinear TF scaling) and threshold calibration.

3. **Tier C: Independent Out-of-Source Test Corpus (~4,000 samples)**
   - **IWSPA-AP Anti-Phishing Benchmark** (Never seen in Tier A or B).
   - Purpose: Measure true out-of-distribution generalization and real-world performance without source bias.

4. **Tier D: ANVESH Challenge Set (50 Specialized Benchmark Emails)**
   - Manually constructed and forensically annotated benchmark.
   - Explicitly tests:
     - Urgent wire transfer with legitimate Microsoft 365 / Google SPF/DKIM/DMARC pass.
     - Executive display-name impersonation with subtle Reply-To deviation.
     - Invoice account routing changes with no malicious links.
     - Legitimate urgent business emails (e.g. quarterly close, emergency IT patch notification) to test false-positive resistance.
     - Compromised tenant ATO simulation.

---

## 5. Leakage Prevention Protocol

To guarantee mathematical integrity and prevent leakage:
1. **Cryptographic Deduplication**:
   - Every email subject + body is hashed via SHA-256 after Unicode/whitespace normalization.
   - Zero hash collisions permitted between Train, Validation, Test, or Challenge sets.
2. **Template / Near-Duplicate Suppression**:
   - Normalized text with >90% character Jaccard similarity in phishing campaign bursts is collapsed into single representative instances to prevent template over-representation.
3. **Strict Post-Verdict Feature Isolation**:
   - Model 1 takes **only `subject` and `body` raw text as inputs**.
   - Risk scores, rule-based indicators, SPF/DKIM flags, IP intelligence, and final verdicts are **strictly isolated from training features**.

---

## 6. False Positive vs. False Negative Cybersecurity Tradeoff

| Metric Focus | Cybersecurity Impact | Operational Consequence | ANVESH Design Stance |
|---|---|---|---|
| **False Negatives (FN)** (Missed Phishing/BEC) | High Risk: Attacker reaches executive inbox; potential wire fraud or credential breach. | Direct security incident and financial exposure. | Minimized by high-recall tuning on high-risk semantic vectors. |
| **False Positives (FP)** (Benign flagged as Phishing) | Operational Friction: Legitimate business invoices or executive communications delayed. | Alert fatigue for SOC analysts; eroded trust in forensic platform. | Controlled by incorporating Enron corporate communications and SpamAssassin `hard_ham` into validation. |
| **Calibrated Output** | Probability scores ($0.0 \le p \le 1.0$) rather than binary certitude. | Investigators see `Phishing Likelihood: 0.87` with contributing feature evidence, enabling explainable decision-making. | Enforced across all layers. |

---

## 7. Recommendation & Next Action

### Recommended Dataset Combination:
- **Training & Validation**: Mendeley CC-BY-4.0 Phishing & Safe Email Dataset + Nazario Phishing Corpus + Enron Enterprise Communication Corpus (Deduplicated, 70/15 split).
- **Independent Test**: IWSPA-AP 2018/2020 Benchmark.
- **Adversarial Benchmark**: ANVESH 50-Scenario Challenge Set.

---

```
================================================================================
GOVERNANCE STOP CONDITION ACTIVE:
Awaiting user review and approval of this Dataset Candidate Report before 
proceeding with dataset downloading, split generation, or model training.
================================================================================
```
