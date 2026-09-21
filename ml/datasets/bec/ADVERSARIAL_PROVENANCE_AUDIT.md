# ANVESH — Adversarial BEC Benchmark Provenance & Evasion Audit

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Audit Target:** `ml/datasets/bec/adversarial_test.jsonl`  
**Audit Phase:** Phase 6D (Provenance & Reproducibility Audit)  
**Governance Invariant:** Model 1, IWSPA, ANVESH Challenge, and Phase 4/5 Artifacts **REMAIN COMPLETELY FROZEN & UNTOUCHED**

---

## 1. Executive Summary

This audit verifies the provenance, generation methodology, adversarial evasion mechanics, and isolation controls for the 300-sample **Adversarial BEC Benchmark**.

### Key Findings:
- **Total Samples:** Exactly 300 records.
- **Label Composition:** 100% Positive BEC (`label: "BEC"`, `target: 1`).
- **Data Classification:** `ADVERSARIAL_SYNTHETIC`.
- **Evasion Techniques Evaluated:**
  1. **Cyrillic Homoglyph Substitution (150 samples / 50%):** Replaces Latin characters in critical keyword tokens (`wire`, `invoice`, `transfer`, `bank`) with visually identical Cyrillic Unicode code points (e.g. Cyrillic `а` (U+0430), `е` (U+0435), `о` (U+043E), `р` (U+0440), `с` (U+0441), `і` (U+0456)).
  2. **Zero-Width Space Unicode Injection (150 samples / 50%):** Injects invisible zero-width spaces (`\u200B`) inside high-confidence token boundaries (e.g. `trans\u200Bfer`, `pay\u200Bment`, `acc\u200Bount`) to fragment standard regex and whitespace-based tokenizers while preserving human visual legibility.
- **Training Contamination Status:** **0% contamination.** Zero adversarial samples were present during Model 2 baseline training.
- **Cross-Partition Overlap:** 0 SHA-256 matches with `train.jsonl`, `val.jsonl`, `independent_test_dube_bec2_pure.jsonl`, `independent_test_enron_heldout.jsonl`, `independent_test_iwspa.jsonl`, or `anvesh_challenge_50.jsonl`.

---

## 2. Granular Record Accounting

| Property | Value |
| :--- | :--- |
| **File Path** | `ml/datasets/bec/adversarial_test.jsonl` |
| **Total Record Count** | **300** |
| **BEC Count** | **300** (100.0%) |
| **NON_BEC Count** | **0** (0.0%) |
| **Homoglyph Samples** | **150** (`evasion_technique: "HOMOGLYPH_SUBSTITUTION"`) |
| **Zero-Width Space Samples** | **150** (`evasion_technique: "ZERO_WIDTH_UNICODE_INJECTION"`) |
| **Clean Counterparts Available** | **Yes** (Derived from unperturbed synthetic BEC seed templates) |
| **SHA-256 Hash of Dataset** | `26d18227658516086f6888fc6b5b5ec1e975cc394145f47055da85913253b27b` |

---

## 3. Evaluation Findings & Correct Statistical Wording

Evaluating Model 2 (`afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8`) on the adversarial benchmark:
- **Detected BEC Samples:** 300 / 300
- **Adversarial Recall:** **100.0%** (0 false negatives)

### Mandatory Statistical Wording:
> **"Model 2 achieved a 100.0% detection rate on the evaluated 300-sample adversarial benchmark partition."**  
> *(We do NOT state "Model 2 has 100% universal adversarial robustness.")*

### Technical Explanation for High Evasion Detection:
The linear TF-IDF model remained effective against character-level perturbations because:
1. Attack prompts retained broader, unperturbed multi-word context and surrounding bigrams (e.g. `urgent wire`, `confidential acquisition`, `new beneficiary account`, `updated remittance`).
2. Even when primary keywords (`transfer`) were fragmented by zero-width spaces, secondary unigrams (`director`, `corporate`, `routing`, `immediate`, `close`) provided sufficient linear positive weight to exceed the 0.50 decision threshold.
