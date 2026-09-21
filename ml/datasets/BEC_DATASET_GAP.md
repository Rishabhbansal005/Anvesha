# ANVESH — Business Email Compromise (BEC) Dataset Gap & Governance Audit

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Phase:** Phase 6 (Model 2: BEC Detection Baseline)  
**Governance Status:** SCIENTIFIC DATASET AUDIT COMPLETE — GOVERNANCE GAP IDENTIFIED  

---

## 1. Executive Summary & Problem Statement

Phase 6 addresses the machine learning architecture for **Model 2: Business Email Compromise (BEC) Detection**.

### The Core Distiction: BEC vs. Generic Phishing
Business Email Compromise (BEC) is fundamentally distinct from bulk generic phishing:
- **Generic Phishing:** High-volume, untargeted or broad credential lures, fake login portals, malicious attachments, and generic consumer bank alerts. Almost always arrives from unaligned, freshly registered, or spoofed sending infrastructure (often triggering SPF/DKIM/DMARC failures or domain age flags).
- **Business Email Compromise (BEC):** Highly targeted social engineering aimed at enterprise accounting, payroll, executive management, or vendor procurement. Key characteristics include:
  1. **Compromised Legitimate Accounts:** Transmitted from authenticated, enterprise mailboxes (Office 365, Google Workspace) where **SPF = PASS, DKIM = PASS, and DMARC = PASS**.
  2. **No Malicious Links / Payloads:** Frequently payload-free plain text, relying purely on conversational authority, urgent invoice rerouting, or payroll diversion.
  3. **Contextual Enterprise Fraud:** Involves executive impersonation, wire transfer redirection, bank account change requests, and vendor remittance manipulation.

---

## 2. Comprehensive Audit of Existing Corpora

We audited all datasets currently cataloged in the ANVESH repository (`ml/datasets/`):

| Dataset Candidate | Original Records | Primary Content | Category Classification | Suitability for BEC Training |
| :--- | :--- | :--- | :--- | :--- |
| **Jose Nazario Phishing Archive** | ~8,150 | Credential harvesting, bank login phishing | **Category B (Generic Phishing)** | **UNSUITABLE for BEC.** Consumer lures; lack enterprise conversational context. |
| **Enron Corporate Email Corpus** | ~517,401 | Authentic enterprise corporate communications | **Category D (Benign Business Email)** | **HIGH SUITABILITY (Negative Class).** Provides gold-standard legitimate business vocabulary, vendor exchanges, and executive tone. |
| **SpamAssassin Public Corpus** | ~6,047 | Commercial spam, newsletters, developer ham | **Category D (Benign General / Spam)** | **PARTIAL (Hard-Ham Benchmark).** Useful for false-positive validation; not representative of BEC attacks. |
| **IWSPA-AP Benchmark** | ~9,000 | Phishing vs. legitimate email competition | **Category B + D (Anti-Phishing Test)** | **FROZEN (Tier C Test Set).** Cannot be used for training under ANVESH governance. |
| **419 / Nigerian Advance-Fee Corpus** | ~2,500 | Lottery scams, inheritance fraud, foreign minister funds | **Category C (Advance-Fee Fraud / Scam)** | **STRICTLY PROHIBITED FROM BEC RELABELING.** Consumer scam letters; completely different structural and behavioral semantics from enterprise BEC. |
| **AIKosh / IndiaAI Platform** | N/A | General NLP / cyber safety text | **Category F (Unknown / Unpublished)** | **UNAVAILABLE.** Raw RFC-822 enterprise email corpora are currently unpublished/restricted. |
| **ANVESH Challenge Benchmark (50)** | 50 | 30 BEC scenarios, 20 Benign enterprise emails | **Category E (Synthetic / Challenge Set)** | **FROZEN (Tier D Benchmark).** Must remain untouched for final product benchmarking. |

---

## 3. Why Existing Data Cannot Simply Be Relabeled

### 3.1 Prohibition on Relabeling Advance-Fee (419) Scams as BEC
A common defect in naive security ML pipelines is treating Nigerian 419 scam emails as "BEC" because both involve money transfers. This is scientifically invalid:
- 419 scams use archaic, high-variance consumer narratives (unclaimed lottery winnings, foreign estates, diplomatic couriers).
- Real BEC targets corporate ERP/invoicing workflows, executive assistants, and CFO wire authorizations using formal corporate English.
- Relabeling 419 scams creates severe false positives on legitimate international business transactions while failing to detect subtle vendor bank change fraud.

### 3.2 Prohibition on Keyword-Based Phishing Relabeling
Relabeling generic phishing emails as BEC simply because they contain tokens like `payment`, `invoice`, `wire`, `urgent`, or `bank` injects massive label noise:
- A generic PayPal credential harvest link contains `payment` and `urgent`, but is structurally generic phishing, not BEC.
- A legitimate monthly vendor invoice also contains `payment`, `invoice`, and `bank`.
- True BEC signals arise from **conversational context, account change patterns, authority coercion, and out-of-band payment diversion**.

---

## 4. The BEC Dataset Gap: What Is Missing?

To train a robust, production-grade Model 2 classifier without overfitting or high false-alarm rates, the following verified data is required:

```
+-------------------------------------------------------------------------------+
|                           AUTHENTIC BEC CORPUS REQUIREMENTS                   |
+-------------------------------------------------------------------------------+
| 1. Executive Impersonation: CEO/CFO urgent wire transfer requests              |
| 2. Vendor Payment Fraud: Supplier bank detail modification notices            |
| 3. Payroll Diversion: Employee direct deposit routing change requests          |
| 4. Invoice / Remittance Manipulation: Intercepted PDF invoices with altered IBAN|
| 5. Compromised Account Conversations: Real thread hijacking from valid tenants|
| 6. Credential Harvesting with Business Context: M365/Google Workspace lure    |
+-------------------------------------------------------------------------------+
```

### Quantitative Gap Analysis
- **Target Training Volume for Model 2:** Minimum 1,500 - 3,000 verified BEC samples paired with 5,000+ Enron/modern business emails.
- **Current Defensible Real-World Public BEC Volume:** ~0 verified enterprise BEC samples in open public academic archives (due to strict confidentiality, PII, and corporate legal non-disclosure).

---

## 5. Proposed Acquisition & Annotation Strategy

1. **Enterprise SOC / CERT-In Anonymized Incident Disclosures:**
   - Partner with enterprise security operation centers to acquire sanitized, PII-scrubbed BEC threat submissions.
2. **Red-Team High-Fidelity Simulations:**
   - Engage certified adversary emulation specialists to author contextual enterprise attack scenarios simulating executive and vendor fraud.
3. **Formal Annotation Schema:**
   - Label: `BEC` (1) vs `NON_BEC` (0)
   - Metadata Subtypes:
     - `EXECUTIVE_IMPERSONATION`
     - `VENDOR_PAYMENT_FRAUD`
     - `BANK_ACCOUNT_CHANGE`
     - `INVOICE_REMITTANCE_FRAUD`
     - `CREDENTIAL_MANIPULATION`
     - `COMPROMISED_ACCOUNT`
     - `OTHER_BEC`

---

## 6. Governance Decision for Phase 6

1. **Production Deployment Blocked for Model 2:**
   - In adherence to the ANVESH Scientific Integrity Principle (*"A smaller defensible BEC model is better than a large fabricated BEC model"*), Model 2 will **NOT** be trained on relabeled 419 scams or generic phishing.
2. **Development Baseline & Notebook Created:**
   - A fully reproducible Google Colab training pipeline (`ml/notebooks/02_bec_baseline_colab.ipynb`) and a clearly isolated synthetic development dataset (`ml/datasets/bec_development_synthetic.jsonl`) marked `SYNTHETIC / DEVELOPMENT ONLY` are provided for pipeline verification and baseline development.
3. **Production Safety Guarantee:**
   - Production FastAPI inference and risk scoring remain powered by **Model 1 (Phishing NLP Signal)** + **Phase 2 Deterministic BEC Indicator Engine** + **Forensic Multi-Hop Infrastructure Intelligence**.

---

## 7. Phase 6B Revision — External Dataset Discovery (2026-09-06)

Following an exhaustive external literature and repository audit:
- **Discovered Peer-Reviewed Datasets:** Identified **Rohit Dube's BEC-2** (Springer 2025, 279 samples) and **Kaggle Adversarial BEC** (2024/2025, 4,211 samples with adversarial evasion).
- **Revision to Training Feasibility:** While raw, real-world intercepted corporate BEC emails remain legally restricted due to PII/NDAs, high-fidelity synthetic and adversarially augmented BEC datasets have established a scientifically viable foundation for **Model 2 Development and Robustness Testing**.
- **Governed Action:** Documented full candidate provenance in `ml/datasets/BEC_EXTERNAL_DATASET_AUDIT.md` and established a governed multi-source formulation in `ml/datasets/BEC_DATASET_RECOMMENDATION.md`. Model 1 and Phase 4/5 artifacts remain completely frozen.

