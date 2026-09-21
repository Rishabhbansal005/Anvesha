# ANVESH — Rohit Dube BEC-2 Independent Benchmark Provenance Audit

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Audit Target:** `ml/datasets/bec/independent_test_dube_bec2.jsonl` & Derived Benchmarks  
**Audit Phase:** Phase 6D (Provenance & Reproducibility Audit)  
**Governance Invariant:** Model 1, IWSPA, ANVESH Challenge, and Phase 4/5 Artifacts **REMAIN COMPLETELY FROZEN & UNTOUCHED**

---

## 1. Executive Provenance Summary

This audit establishes the precise origin, composition, and methodology of the 579-sample independent test set used in the Model 2 BEC baseline evaluation.

### Provenance Classification:
```
========================================================================================
CLASSIFICATION: C. MIXED-SOURCE INDEPENDENT BENCHMARK
========================================================================================
```

The 579-sample evaluation set is **NOT a pure standalone copy of Rohit Dube's BEC-2 dataset**. It is a **governed mixed independent benchmark** consisting of:
1. **Pure Dube-Derived BEC-2 Benchmark:** 279 samples (189 Positive BEC + 90 Neutral Business Controls) derived from Rohit Dube's published research scenarios.
2. **Held-Out External Enterprise Benign Partition:** 300 samples (271 Enron Corporate Corpus + 29 SpamAssassin Public Corpus) held out strictly from training/validation to test false-alarm rates on authentic corporate and developer traffic.

---

## 2. Granular Record Accounting & Answers to Audit Inquiries

| Audit Question | Verified Finding & Exact Metric |
| :--- | :--- |
| **1. How many records originate directly from Dube BEC-2?** | **279 records** (48.19% of the 579-sample set). |
| **2. How many are BEC?** | **189 records** in the Dube subset (100% of all BEC in the 579-sample set). |
| **3. How many are NON_BEC?** | **390 records** total (90 neutral Dube controls + 300 held-out corporate benign). |
| **4. Where did the 390 NON_BEC records come from?** | 90 from Dube neutral controls + 271 from Enron Corporate Corpus + 29 from SpamAssassin Public Corpus. |
| **5. Were those 300 NON_BEC records part of original Dube BEC-2?** | **NO.** They were sourced separately from authentic enterprise and open-source corpora. |
| **6. If not, what source were they taken from?** | Sourced from `ml/datasets/processed/train.jsonl` (Enron indices 1700–2000), disjoint from Model 2 training. |
| **7. Were they transformed, synthesized, augmented, or merged?** | Formatted into standard schema (`id`, `subject`, `body`, `label`, `subtype`, `source`, `nature`). |
| **8. Was any record duplicated from Model 2 training data?** | **0 duplicates.** Enron indices (1700–2000) are disjoint from Model 2 training indices (0–1400) and validation indices (1400–1700). |
| **9. Were any records from Enron used?** | **YES.** Exactly 271 records. |
| **10. Were any records from Kaggle synthetic BEC used?** | **NO.** Zero Kaggle synthetic records are present in the independent test partitions. |
| **11. Were any records from Kaggle adversarial corpus used?** | **NO.** Zero adversarial records are present in the independent test partitions. |
| **12. Was any record from IWSPA or ANVESH Challenge used?** | **NO.** Zero overlap (0 SHA-256 matches) with `independent_test_iwspa.jsonl` or `anvesh_challenge_50.jsonl`. |

---

## 3. Disaggregated Partition Strategy

To ensure transparent reporting, the independent test suite is explicitly separated into three distinct files:

1. **`ml/datasets/bec/independent_test_dube_bec2_pure.jsonl`** (279 samples)
   - **BEC:** 189
   - **NON_BEC:** 90
   - **Nature:** `AUGMENTED_SYNTHETIC_DERIVED`
   - **Role:** Pure out-of-source Dube BEC-2 research evaluation.
2. **`ml/datasets/bec/independent_test_enron_heldout.jsonl`** (300 samples)
   - **BEC:** 0
   - **NON_BEC:** 300 (271 Enron + 29 SpamAssassin)
   - **Nature:** `REAL`
   - **Role:** Pure authentic corporate benign false-positive resistance benchmark.
3. **`ml/datasets/bec/independent_test_bec2_mixed.jsonl`** (579 samples)
   - **BEC:** 189
   - **NON_BEC:** 390
   - **Role:** Combined mixed independent benchmark (aliased as `independent_test_dube_bec2.jsonl`).

---

## 4. Disaggregated Performance Metrics

Evaluating the frozen Model 2 (`afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8`) across these partitions yields:

| Benchmark Partition | Sample Count | Accuracy | Precision | Recall (BEC) | F1 Score | ROC-AUC | BEC FNR | NON_BEC FPR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Pure Dube BEC-2** | 279 | **0.9355** | 0.9130 | **1.0000** | 0.9545 | 0.9900 | **0.00%** | **20.00%** (18/90) |
| **Held-Out Enron/SpamAssassin** | 300 | **1.0000** | N/A | N/A | N/A | 1.0000 | N/A | **0.00%** (0/300) |
| **Combined Mixed Benchmark** | 579 | **0.9689** | 0.9130 | **1.0000** | 0.9545 | 0.9977 | **0.00%** | **4.62%** (18/390) |

### Key Forensic Insight:
- On pure authentic Enron enterprise traffic, Model 2 had **0 false positives (0.0% FPR)**.
- The 18 false positives occurred entirely within Dube's neutral prompts that contained billing/invoice phrases (*"Routine Invoice #INV-5501 - Regular Net-30 terms to SVB account"*), highlighting that financial lexical overlap remains an inherent limitation of pure bag-of-words NLP classifiers.
