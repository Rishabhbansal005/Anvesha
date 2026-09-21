# ANVESH — BEC Dataset Strategy & Governance Recommendation

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Phase:** Phase 6B (Dataset Strategy & Governance Recommendation)  
**Governance Invariant:** Model 1, IWSPA Independent Test, ANVESH Challenge, and Phase 4/5 Artifacts **REMAIN FROZEN & UNTOUCHED**

---

## 1. Governance Decision: GO / NO-GO

```
========================================================================================
RECOMMENDATION: OPTION A — PROCEED TO GOVERNED MODEL 2 BASELINE TRAINING (DEVELOPMENT CORPUS)
========================================================================================
```

### Rationale
Our external discovery audit revealed two peer-reviewed and open-licensed synthetic BEC datasets that satisfy strict forensic integrity requirements:
1. **Rohit Dube's BEC-2 Dataset** (2025 Springer Journal of Computer Virology / arXiv:2407.20235) — 279 verified samples with a 93% human analyst agreement score.
2. **Kaggle Adversarial BEC Dataset** (2024/2025) — 4,211 synthetic samples with explicit adversarial evasion techniques (homoglyphs and zero-width spaces).

By combining these positive BEC sources with authentic negative enterprise communications from **Enron Corporate Email** and **SpamAssassin Hard-Ham**, we can formulate a balanced, statistically sound, multi-source training and independent evaluation benchmark.

---

## 2. Proposed Governed Corpus Composition

```
+---------------------------------------------------------------------------------------+
|                               ANVESH MODEL 2 HYBRID CORPUS                            |
+---------------------------------------------------------------------------------------+
| POSITIVE CLASS (BEC = 1):                                                             |
| - Kaggle Clean Synthetic BEC: ~2,500 samples (Training Partition)                     |
| - Kaggle Poisoned Adversarial BEC: ~1,200 samples (Adversarial Robustness Test)       |
| - Rohit Dube BEC-2: ~262 samples (Out-of-Source Independent Generalization Test)       |
+---------------------------------------------------------------------------------------+
| NEGATIVE CLASS (NON_BEC = 0):                                                         |
| - Enron Corporate Business Email: ~3,500 samples (Legitimate business/invoice context)|
| - SpamAssassin Hard-Ham: ~250 samples (Non-business ham false-positive resilience)    |
| - Rohit Dube Neutral Business: ~17 samples (Independent Negative Control)              |
+---------------------------------------------------------------------------------------+
```

---

## 3. Independent Cross-Source Evaluation Strategy

To prevent overfitting and evaluate true generalization:
- **Training Corpus (Tier A):** Kaggle Clean Synthetic BEC (Positive) + Enron Business Subset (Negative).
- **Independent Test Corpus (Tier C - Out-of-Source):** **Rohit Dube BEC-2** (Completely held out from training) + Held-Out Enron Executive Accounts.
- **Adversarial Robustness Benchmark:** **Kaggle Poisoned Dataset** (Evasion techniques with zero-width characters and homoglyphs).

### Core Research Questions Answered:
1. *"Does a model trained on Kaggle BEC generalize to Dube's independently generated BEC dataset?"*
2. *"Does the model withstand adversarial Unicode and homoglyph evasion attempts?"*
3. *"Does the model maintain near-zero false positive rates on authentic Enron executive communications?"*

---

## 4. Leakage & Boundary Safeguards

1. **Zero Overlap with Model 1 Benchmarks:** All Model 2 partitions remain strictly isolated from `independent_test_iwspa.jsonl` and `anvesh_challenge_50.jsonl`.
2. **Feature Boundary Invariant:** Model 2 strictly receives **Subject + Body** text. No network, DNS, RDAP, or authentication features are provided to the ML pipeline.
3. **Transparent Staging:** Model 2 will remain in development/evaluation staging until the full source-aware holdout and adversarial benchmarks are formally approved.
