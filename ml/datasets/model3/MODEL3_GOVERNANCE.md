# ANVESH — Model 3 Governance Specification & Dataset Gap Notice

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Architecture:** Model 3 (Identity Impersonation & Lookalike Domain Scoring)  
**Phase:** Phase 7B (Model 3 Dataset Governance & Provenance Correction)  
**Governance Invariant:** Model 1, Model 2, IWSPA, and ANVESH Challenge **REMAIN COMPLETELY FROZEN & UNTOUCHED**  
**Execution Mode:** GOVERNANCE POLICY SPECIFICATION ONLY (No Training Executed)

---

## 1. Architectural Bifurcation: Model 3A vs. Model 3B

```
+-----------------------------------------------------------------------------------------------+
|                                ANVESH MODEL 3 MODULAR ARCHITECTURE                            |
+-----------------------------------------------------------------------------------------------+
| MODEL 3A: Identity & Header Impersonation Scoring                                            |
| - Target: Display-name deception, internal executive spoofing, Reply-To discrepancy          |
| - Status: DATASET GAP (Public Ground-Truth Identity Impersonation Data Unavailable)           |
| - Action: TRAINING BLOCKED. No synthetic data manufactured.                                  |
+-----------------------------------------------------------------------------------------------+
| MODEL 3B: Lookalike Domain & Typosquatting Scoring                                            |
| - Target: Domain-level mimicry, visual homoglyphs, brand abuse, and DNS/RDAP signals          |
| - Status: READY FOR GOVERNED TRAINING (Verified Zenodo & GlyphNet Benchmarks)                |
| - Action: APPROVED TO PROCEED UPON EXPLICIT USER AUTHORIZATION.                               |
+-----------------------------------------------------------------------------------------------+
```

---

## 2. Model 3A Dataset Gap & Governance Policy

1. **Removal of Unverified Claims:** The prior reference to *"Enron Executive Identity Corpus — 50k+"* has been formally struck down. While the Enron Corporate Email Corpus contains authentic corporate messages, it **does not contain ground-truth display-name spoofing or executive impersonation labels**.
2. **Prohibition on Keyword Relabeling:** In accordance with ANVESH scientific integrity, searching for tokens like `CEO`, `wire`, `urgent`, or `bank` within benign corpora to create synthetic positive labels is **strictly prohibited**.
3. **Classification:** **`MODEL 3A = DATASET GAP (TRAINING BLOCKED)`**. No training of Model 3A will occur until permissioned enterprise SOC telemetry with authentic identity spoofing is acquired.

---

## 3. Model 3B Governed Dataset Specifications

Model 3B evaluates lexical string distances, visual homoglyph collisions, and DNS/RDAP infrastructure features. The following verified datasets are approved for Model 3B:

| Candidate Dataset | Source URL / DOI | Exact Sample Count | License | Available Fields | Model 3B Partition Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Zenodo DNS Domain Intel ("Spotting the Hook")** | [10.5281/zenodo.8364668](https://doi.org/10.5281/zenodo.8364668) | **436,000+** (400k+ Benign / 36k+ Phishing) | **CC BY 4.0** | `domain_name`, `dns_records` (A/AAAA/MX/NS/TXT), `whois_rdap` (creation, expiry), `tls_certs`, `ip_addresses`, `geoip`, `label` | **Training & In-Source Validation (Tier A/B)** |
| **Zenodo Brand Impersonation Dataset** | [10.5281/zenodo.8041387](https://doi.org/10.5281/zenodo.8041387) | **10,395** (5,244 Legitimate / 5,151 Phishing) | **CC BY 4.0** | `domain_name`, `target_brand` (86 brands mapped in `brands.csv`), `whois`, `ssl`, `ip`, `label` | **Out-of-Source Independent Test Benchmark (Tier C)** |
| **GlyphNet & dnstwist Homoglyph Corpus** | `https://github.com/elceef/dnstwist` / arXiv:2302.04652 | **4,050,000+** | **MIT / Open** | `original_domain`, `permuted_domain`, `permutation_type` (Homoglyph, Bit-squatting, Omission, TLD-swap), `punycode` | **Algorithmic Evasion & Distance Benchmark (Tier D)** |

---

## 4. Independent Test Set & Leakage Safeguards for Model 3B

1. **Independent Evaluation Source:** The **Zenodo Brand Impersonation Dataset (10,395 records / 86 brands)** will serve as the 100% held-out independent test benchmark.
2. **Domain Pair Disjointness:** No target brand or domain pair present in training (e.g. `microsoft.com` $\rightarrow$ `micros0ft.com`) may appear in the validation or independent evaluation partitions.
3. **Zero Contamination of Frozen Artifacts:** Zero overlap with `independent_test_iwspa.jsonl` (SHA-256: `a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552`) or `anvesh_challenge_50.jsonl` (SHA-256: `a5abe63187a59eb32c730ec2dd0f7d248629fd7a50679baaa296bd224092c68f`).

---

## 5. Governance Confirmation — Frozen Status of Models 1 & 2

| Frozen Artifact | Status | Expected SHA-256 Hash |
| :--- | :--- | :--- |
| `ml/models/phishing_baseline_v1/model.joblib` | **FROZEN** | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` |
| `ml/models/bec_baseline_v1/model.joblib` | **FROZEN** | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` |
| `ml/datasets/processed/independent_test_iwspa.jsonl` | **FROZEN** | `a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552` |
| `ml/datasets/challenge/anvesh_challenge_50.jsonl` | **FROZEN** | `a5abe63187a59eb32c730ec2dd0f7d248629fd7a50679baaa296bd224092c68f` |

**Final Statement:**
> **"Phase 4 and Phase 6 ML/evaluation artifacts remain frozen and unchanged."**
