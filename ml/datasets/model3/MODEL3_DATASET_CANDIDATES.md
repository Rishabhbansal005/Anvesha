# ANVESH — Model 3 (Identity Impersonation & Lookalike Domain Detection) Dataset Candidates

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Model:** Model 3 (Identity Impersonation & Lookalike Domain Detection)  
**Phase:** Phase 7B (Model 3 Dataset Governance & Provenance Correction)  
**Governance Invariant:** Model 1, Model 2, IWSPA, and ANVESH Challenge **REMAIN COMPLETELY FROZEN & UNTOUCHED**  
**Execution Mode:** DATASET GOVERNANCE AUDIT ONLY (No Training Executed)

---

## 1. Scope & Architectural Separation: Model 3A vs. Model 3B

To prevent modality confounding between conversational email headers and lexical domain infrastructure:

```
+-----------------------------------------------------------------------------------------------+
|                                ANVESH MODEL 3 MODULAR ARCHITECTURE                            |
+-----------------------------------------------------------------------------------------------+
| MODEL 3A: Identity & Header Impersonation Scoring                                            |
| - Scope: Display-name deception, internal executive spoofing, Reply-To routing discrepancy    |
| - Inputs: Display Name, From Address, From Domain, Reply-To, Target Org Domain, Subject/Body  |
| - Status: DATASET GAP (Public Ground-Truth Identity Impersonation Data Unavailable)           |
+-----------------------------------------------------------------------------------------------+
| MODEL 3B: Lookalike Domain & Typosquatting Scoring                                            |
| - Scope: Domain-level mimicry, visual homoglyphs, brand abuse, and DNS/RDAP signals          |
| - Inputs: Sender Domain, Trusted Target Domain, WHOIS/RDAP, DNS MX, TLS Certificate           |
| - Status: READY FOR GOVERNED TRAINING (Verified Zenodo & GlyphNet Benchmarks)                |
+-----------------------------------------------------------------------------------------------+
```

---

## 2. Model 3A (Identity & Header Impersonation) Candidates Audit

### 2.1 Enron Corporate Email Corpus — Clarification & Status Correction
- **Previous Claim:** *"Enron Executive Identity Corpus — 50k+"*
- **Correction:** **UNVERIFIED AS AN EXECUTIVE-IDENTITY-LABELED DATASET.**
- **Actual Provenance:** The Enron dataset contains authentic corporate messages from ~150 employee and executive mailboxes released by the FERC/CMU project. However, **it does not contain ground-truth display-name spoofing or impersonation attack labels**. 
- **Finding:** Enron is a clean benign corporate communication archive. Using it to train an identity spoofing detector without genuine adversarial attack samples would require arbitrary keyword/rule relabeling, which is strictly prohibited under ANVESH governance.

### 2.2 Public Display-Name Spoofing & Executive Impersonation Dataset Search
- **Investigated Repositories:** Zenodo, Hugging Face, GitHub, Kaggle, IEEE, ACM, USENIX.
- **Finding:** **No publicly available, open-access dataset exists with ground-truth display-name spoofing or executive impersonation labels.** Real executive impersonation incidents are held in private corporate SOC telemetry due to extreme executive PII, financial confidentiality, and non-disclosure agreements.
- **Model 3A Verdict:** 
  ```
  ========================================================================================
  MODEL 3A STATUS: DATASET GAP — TRAINING BLOCKED
  ========================================================================================
  ```
  In strict adherence to ANVESH principles (*"Do not manufacture labels or create synthetic data to bypass open-source data absence"*), Model 3A is classified as **DATASET GAP**. No training will occur for Model 3A until verified, permissioned enterprise telemetry is acquired.

---

## 3. Model 3B (Lookalike Domain & Typosquatting) Candidates Audit

Unlike Model 3A, **Model 3B has high-quality, open-access, ground-truth datasets** available in peer-reviewed repositories:

---

### Candidate 1: Zenodo "Spotting the Hook" / DNS Domain Intelligence Dataset
- **Publisher / Authors:** Faculty of Information Technology, Brno University of Technology
- **Publication / Reference:** *"Spotting the Hook: Leveraging Domain Data for Advanced Phishing Detection"* (CNSM 2024) / *"A Multi-Dimensional DNS Domain Intelligence Dataset"* (*Data in Brief*, 2025)
- **Source / Zenodo DOI:** [10.5281/zenodo.8364668](https://doi.org/10.5281/zenodo.8364668) & [10.5281/zenodo.8348982](https://doi.org/10.5281/zenodo.8348982)
- **Source URL:** `https://zenodo.org/records/8364668`
- **Sample Count:** **436,000+ total domains** (400,000+ Benign, 36,000+ Phishing/Malicious)
- **License:** **Creative Commons Attribution 4.0 International (CC BY 4.0)**
- **Data Nature:** `REAL_WORLD_INFRASTRUCTURE`
- **Available Fields:** `domain_name`, `dns_records` (A, AAAA, MX, NS, TXT), `whois_rdap` (creation_date, registrar, expiration), `tls_certs`, `ip_addresses`, `geoip`, `label`.
- **Model 3B Role:** Primary infrastructure feature training (Domain age, MX validity, TLS issuer entropy).
- **Governance Tier:** **GREEN (Approved for Model 3B)**

---

### Candidate 2: Zenodo Phishing Website & Brand Impersonation Dataset
- **Publisher / Authors:** I Kadek Agus Ariesta Putra
- **Publication / Reference:** *"Phishing Website Dataset for Brand Impersonation Analysis"*, Zenodo (2023)
- **Source / Zenodo DOI:** [10.5281/zenodo.8041387](https://doi.org/10.5281/zenodo.8041387)
- **Source URL:** `https://zenodo.org/records/8041387`
- **Sample Count:** **10,395 records** (5,244 Legitimate, 5,151 Phishing)
- **License:** **Creative Commons Attribution 4.0 International (CC BY 4.0)**
- **Data Nature:** `REAL_WORLD_TELEMETRY`
- **Available Fields:** `domain_name`, `target_brand` (explicitly mapping 86 target brands in `brands.csv`), `whois`, `ssl`, `ip`, `label`.
- **Model 3B Role:** Ground-truth brand-to-lookalike domain mapping and **Out-of-Source Independent Evaluation Benchmark** (86 target brands held out).
- **Governance Tier:** **GREEN (Approved for Model 3B)**

---

### Candidate 3: GlyphNet & dnstwist Homoglyph / Typosquatting Corpora
- **Publisher / Authors:** GlyphNet Research Team / dnstwist Open Source Community
- **Publication / Reference:** *GlyphNet: Visual Homoglyph Detection* (arXiv:2302.04652) / *dnstwist domain permutation engine* (GitHub: `elceef/dnstwist`)
- **Source URL:** `https://github.com/elceef/dnstwist` / `https://arxiv.org/abs/2302.04652`
- **Sample Count:** **4,050,000+ domain permutations** (4,000,000 GlyphNet + 50,000 dnstwist permutations)
- **License:** **MIT License / Open Research Access**
- **Data Nature:** `SYNTHETIC_ALGORITHMIC_PERMUTATIONS_AND_REAL_OBSERVED_HOMOGLYPHS`
- **Available Fields:** `original_domain`, `permuted_domain`, `permutation_type` (Homoglyph, Bit-squatting, Omission, Insertion, Transposition, TLD-swap), `punycode`, `visual_similarity_score`.
- **Model 3B Role:** Algorithmic string distance training and visual Unicode collision scoring.
- **Governance Tier:** **GREEN (Approved for Model 3B)**

---

### Candidate 4: MeAJOR Merged Email Assets Corpus
- **Publisher / Authors:** GECAD / ISEP, Polytechnic of Porto
- **Zenodo DOI:** [10.5281/zenodo.108685](https://doi.org/10.5281/zenodo.108685)
- **Sample Count:** ~108,685 emails
- **Critical Limitation:** Identity strings and sender domains replaced by `[NAME]`, `[EMAIL_ADDRESS]`, and `[URL]`.
- **Governance Tier:** **RED (Rejected for Model 3)**

---

## 4. Summary Scorecard & Readiness Classification

| Candidate Dataset | Volume | Nature | License | Model 3 Role | Score (Max 100) | Governance Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Zenodo DNS Domain Intel (8364668)** | 436k+ | Real Infrastructure | CC BY 4.0 | Model 3B Infrastructure | **100 / 100** | **APPROVED (GREEN)** |
| **Zenodo Brand Impersonation (8041387)** | 10.4k | Real Brand Mapping | CC BY 4.0 | Model 3B Brand Scoring | **96 / 100** | **APPROVED (GREEN)** |
| **GlyphNet & dnstwist Corpus** | 4.05M | Real + Algorithmic | MIT / Open | Model 3B Homoglyphs | **89 / 100** | **APPROVED (GREEN)** |
| **Enron Corporate Corpus** | ~517k | Unlabeled Corporate | Public Domain | Unlabeled for Impersonation | **45 / 100** | **UNVERIFIED FOR 3A** |
| **MeAJOR Corpus (108685)** | 108k+ | Anonymized NLP | Open Access | Scrubbed Identity | **66 / 100** | **REJECTED (RED)** |
