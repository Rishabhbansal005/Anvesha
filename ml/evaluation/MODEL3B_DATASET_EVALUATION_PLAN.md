# ANVESH — Model 3B Evaluation & Baseline Comparison Plan

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Model:** Model 3B (Lookalike Domain & Brand Impersonation Detection)  
**Phase:** Phase 7C (Evaluation Planning & Baseline Architecture Design)  
**Governance Invariant:** Model 1, Model 2, IWSPA, and ANVESH Challenge **REMAIN COMPLETELY FROZEN & UNTOUCHED**  
**Execution Mode:** EVALUATION PLAN SPECIFICATION ONLY (No training executed)

---

## 1. Evaluation Objectives

The objective of Model 3B is to detect whether a sender domain is an adversarial lookalike, typosquat, homoglyph, or brand-impersonating domain targeting an organization or recognized brand.

To guarantee forensic explainability and prevent unnecessary ML complexity, Model 3B development follows a rigorous **two-stage benchmark design**:
1. **Deterministic Lexical Baseline:** A rule-based forensic heuristic built purely on edit distances, Jaro-Winkler scores, and homoglyph/Punycode flags.
2. **Machine Learning Model Comparison:** Comparing explainable linear and tree-based classifiers against the deterministic baseline to determine whether ML delivers statistically meaningful improvements.

---

## 2. Stage 1: Deterministic Lexical Baseline Specification

Before fitting any machine learning model, a deterministic rule-based heuristic will be benchmarked on the exact same partitions:

### Deterministic Decision Logic:
A domain pair is classified as `LOOKALIKE_DOMAIN` (1) if ANY of the following deterministic conditions are satisfied:
1. **Low Normalized Edit Distance:** `normalized_edit_distance <= 0.25` AND `normalized_edit_distance > 0.0` (1–2 character substitutions, insertions, or deletions).
2. **High String Similarity:** `jaro_winkler >= 0.88` AND `trusted_domain != candidate_domain`.
3. **Unicode / Homoglyph Presence:** `has_homoglyph == 1` OR `is_punycode == 1`.
4. **Target Brand Deceptive Subdomain:** `brand_in_subdomain == 1` (e.g. `paypal.com.login-verify.biz`).
5. **Digit Leetspeak Substitution:** `digit_substitution_count >= 1` AND `normalized_edit_distance <= 0.35`.

Otherwise, classified as `LEGITIMATE_DOMAIN` (0).

---

## 3. Stage 2: Machine Learning Model Candidates to Compare

If the ML models do not outperform the deterministic heuristic in recall or false-positive rate, ANVESH will adopt the deterministic engine for production simplicity and forensic transparency.

### Candidate ML Architectures:
1. **Model A: Logistic Regression on Engineered Domain Features**
   - Features: 10 structured features (`normalized_edit_distance`, `jaro_winkler`, `has_homoglyph`, `is_punycode`, `digit_substitution_count`, `hyphen_count_diff`, `tld_match`, etc.).
   - Regularization: L2 penalty ($C=1.0$), `class_weight="balanced"`.
   - Advantage: Direct coefficient interpretability for analyst evidence cards.
2. **Model B: Random Forest / Gradient Boosting (Decision Trees)**
   - Estimators: 100 shallow decision trees (`max_depth=4` to prevent memorizing specific brand strings).
   - Advantage: Captures non-linear feature interactions (e.g. TLD swap combined with digit substitution).
3. **Model C: Character-Level N-Gram TF-IDF Baseline**
   - Extractor: Char n-grams (2 to 5 chars) on raw domain strings.
   - Purpose: Validates whether structured domain distance features are superior to raw text tokenization.

---

## 4. Prioritized Evaluation Metrics

Model selection will not optimize purely for accuracy. Decisions will be guided by:
1. **Lookalike Recall (Sensitivity):** Priority metric — missing an active impersonation domain allows credential/wire fraud. Target: $\ge 95\%$.
2. **Legitimate False Positive Rate (FPR):** Priority operational metric — false alarms on legitimate internal subdomains or partner domains break mail flow. Target: $\le 3\%$.
3. **Precision & F1-Score:** Harmonic balance of detection accuracy.
4. **ROC-AUC & PR-AUC:** Discrimination capability across decision thresholds.
5. **Out-of-Brand Generalization:** Performance delta between in-source validation and out-of-source independent evaluation.

---

## 5. Independent & Adversarial Evaluation Sequence

1. **In-Source Validation (`val.jsonl`):** 112 samples across 7 held-out brands.
2. **Out-of-Source Independent Benchmark (`independent_test.jsonl`):** 255 samples across 15 strictly held-out brands (ADP, Adobe, Amazon, American Express, Atlassian, Binance, LinkedIn, Oracle, PayPal, QuickBooks, Salesforce, Square, UPS, Zoom, eBay).
3. **Adversarial Evasion Benchmark (`adversarial_test.jsonl`):** 99 samples evaluating multi-character Cyrillic homoglyphs and Punycode collisions.
