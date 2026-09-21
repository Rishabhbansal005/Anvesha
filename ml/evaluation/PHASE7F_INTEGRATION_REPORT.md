# ANVESH Phase 7F — Model 3B Lookalike Detection Integration Report

**Target Model:** Model 3B (`lookalike_domain_v1`)  
**Status:** Integrated & Frozen (Development / Operational Forensic Staging)  
**Governance Invariants:** Model 1, Model 2, IWSPA, and ANVESH Challenge **FROZEN & VERIFIED UNCHANGED**

---

## 1. Executive Summary
Phase 7F successfully integrated **Model 3B (Lookalike Domain / Brand Impersonation Detection)** into the ANVESH forensic intelligence platform without modifying the frozen binary phishing model (Model 1), the development BEC baseline (Model 2), or existing cryptographic/SPF/DKIM/DMARC/IP forensic risk evaluations.

### Core Architectural Principles Enforced
1. **Mandatory Defense-in-Depth:** A **Tier 1 Deterministic Security Layer** (`HOMOGLYPH_DECEPTION`, `PUNYCODE_IDN_SPOOF`, `SUBDOMAIN_LURE`) runs before the **Tier 2 Random Forest Model**. The deterministic invariants are authoritative and **CANNOT be overridden or downgraded** by low machine-learning probability outputs.
2. **Fail-Closed Integrity Check:** At initialization, Model 3B verifies its SHA-256 checksum against `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559`. If corrupted or missing, it fails closed with `ModelIntegrityError`.
3. **Strict Non-Attribution Invariant:** Model 3B produces **infrastructure and domain similarity evidence only**. It strictly **does NOT establish or claim physical actor identity, geolocation, or malicious intent with certainty**.
4. **Uncalibrated Probability Reporting:** All scores produced by the Random Forest are labeled as **raw model score** or **uncalibrated model score**, never calibrated Bayesian probabilities.

---

## 2. Files Changed & Files Not Changed

### Files Created:
- `ml/inference/lookalike_predictor.py` — Tiered inference engine implementing exact 10 lexical features, SHA-256 verification, Tier 1 invariants, and Random Forest evaluation.
- `backend/app/services/lookalike_service.py` — High-level lookalike service mapping candidate domains against curated high-risk corporate target domains.
- `backend/tests/test_lookalike_pipeline.py` — 11 unit tests covering all 10 governance test scenarios and FastAPI endpoint verification.
- `ml/evaluation/PHASE7F_INTEGRATION_REPORT.md` — This authoritative integration report.

### Files Modified:
- `backend/app/services/risk_engine.py` — Added `evaluate_lookalike_risk(...)` and added `lookalike_impersonation_risk` (0-15 points) category score without breaking existing SPF/DKIM/DMARC/IP/BEC scores.
- `backend/app/api/v1/endpoints/emails.py` — Added `POST /api/v1/emails/lookalike-detect` endpoint and integrated automated lookalike extraction on email analysis.
- `web/src/types/index.ts` — Added `LookalikeEvidence` schema and `lookalike_impersonation_risk` to `CategoryScores`.
- `web/src/pages/InvestigationWorkspace.tsx` — Added 5th category score card and dedicated `LOOKALIKE DOMAIN ANALYSIS` inspection tab.
- `mobile/src/screens/QuickLookupScreen.tsx` — Added automatic domain detection querying Model 3B and rendering operational `HIGH — LOOKALIKE DOMAIN` card with `[View Evidence]` toggle.
- `ml/evaluation/MODEL3B_BASELINE_EVALUATION.md` — Added Phase 7E documentation fixes (QuickBooks/Intuit parentage limitation, academic multi-model evaluation note, defense-in-depth architecture).
- `ml/datasets/model3/MODEL3B_DATASET_AUDIT.md` — Added Phase 7E documentation fixes.

### Files Strictly NOT Changed (Invariants Preserved):
- `ml/models/phishing_baseline_v1/model.joblib` (Model 1 weights)
- `ml/models/phishing_baseline_v1/metadata.json` (Model 1 metadata)
- `ml/models/phishing_baseline_v1/top_features.json` (Model 1 top features)
- `ml/models/bec_baseline_v1/model.joblib` (Model 2 weights)
- `ml/models/bec_baseline_v1/metadata.json` (Model 2 metadata)
- `ml/models/lookalike_domain_v1/model.joblib` (Model 3B weights - NOT retrained)
- `ml/datasets/processed/independent_test_iwspa.jsonl` (IWSPA test partition)
- `ml/datasets/challenge/anvesh_challenge_50.jsonl` (ANVESH Challenge 50)
- Model 3A codebase (Permanently remains `DATASET GAP / TRAINING BLOCKED`)

---

## 3. Model 3B Integrity Verification & Startup Checks
- **Expected Artifact:** `ml/models/lookalike_domain_v1/model.joblib`
- **Verified SHA-256:** `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559`
- **Integrity Enforcement:** `LookalikePredictor._load_and_verify()` hashes the file on initialization. Any alteration raises `ModelIntegrityError` and aborts prediction.
- **Scikit-Learn Compatibility:** Verified matching environment version `1.7.1`.

---

## 4. Tier 1 Deterministic Security Layer Behavior
The deterministic layer operates before the Random Forest structural model:

1. **Homoglyph Deception:**
   - Any character with `ord(c) > 127` triggers `HOMOGLYPH_DECEPTION`.
   - **Signal forced to `HIGH`** regardless of ML output.
   - *Example:* `рayрal.com` (Cyrillic 'р') $	o$ `HOMOGLYPH_DECEPTION` (Signal: `HIGH`).
2. **Punycode IDN Spoofing:**
   - Any domain with `xn--` triggers `PUNYCODE_IDN_SPOOF`.
   - **Signal forced to `HIGH`** regardless of ML output.
   - *Example:* `xn--pple-43d.com` $	o$ `PUNYCODE_IDN_SPOOF` (Signal: `HIGH`).
3. **Subdomain Lure:**
   - Untrusted domain embedding a trusted brand token in its subdomain (e.g. `paypal.com.account-verify.xyz`) triggers `SUBDOMAIN_LURE`.
   - **Signal forced to `HIGH`** regardless of ML output.
4. **Authentic Domain:**
   - Matching or legitimate verified subdomain (e.g. `login.microsoft.com` $	o$ `microsoft.com`) produces `AUTHENTIC_DOMAIN` with signal `NONE` and raw model score `0.0`.

---

## 5. API Integration & Result Schema

FastAPI Endpoint: `POST /api/v1/emails/lookalike-detect`
```json
{
  "candidate_domain": "xn--pple-43d.com",
  "trusted_domain": "apple.com"
}
```

Response Schema:
```json
{
  "model": "lookalike_domain_v1",
  "candidate_domain": "xn--pple-43d.com",
  "trusted_domain": "apple.com",
  "signal": "HIGH",
  "raw_model_score": 0.2000,
  "deterministic_indicators": [
    "PUNYCODE_IDN_SPOOF"
  ],
  "features": {
    "levenshtein_distance": 10.0,
    "normalized_edit_distance": 0.7143,
    "jaro_winkler": 0.4488,
    "length_diff": 9.0,
    "tld_match": 1.0,
    "has_homoglyph": 0.0,
    "is_punycode": 1.0,
    "digit_substitution_count": 0.0,
    "hyphen_count_diff": 2.0,
    "brand_in_subdomain": 0.0
  },
  "explanation": [
    "RFC-3492 Punycode (xn--) internationalized domain encoding observed."
  ],
  "model_status": "FROZEN"
}
```

---

## 6. Risk Engine Integration
Integrated via `RiskEngine.evaluate_lookalike_risk(...)`:
- **Categorical Attribution:** Score (0-15 points) is isolated under `lookalike_impersonation_risk`.
- **Precedence & Independence:** Does NOT override SPF, DKIM, DMARC, Received hop trajectory, or IP reputation.
- **Attribution Guardrail:** High signal appends:  
  `"LOOKALIKE DOMAIN SIGNAL: HIGH - Observed indicator: {indicator}. Candidate '{candidate}' resembles trusted '{trusted}'. Infrastructure/domain evidence only."`

---

## 7. Web UI & Mobile Integration

### Web Investigation Workspace:
- Added **`Lookalike Domain (M3B)`** tab in the forensic sidebar.
- Displays: Candidate Domain, Trusted Domain, Signal badge, Deterministic Indicators with status dots, Structural Lexical Evidence table (Jaro-Winkler, Edit Distance, Levenshtein, TLD Match, Digit Substitutions), and Raw Model Score.
- Disclaimer displayed: *"Domain similarity evidence indicates possible impersonation infrastructure. This does not establish attacker identity."*
- Added 5th category score card in the Overview risk breakdown.

### Mobile On-Call Companion (`QuickLookupScreen`):
- Automatically routes domain queries to `/emails/lookalike-detect`.
- Renders operational card:
  - `HIGH — LOOKALIKE DOMAIN`
  - `xn--pple-43d.com`
  - `PUNYCODE_IDN_SPOOF`
  - Clean `[View Evidence]` toggle displaying Jaro-Winkler, Edit Distance, and Non-Attribution Disclaimer.

---

## 8. Test Results & Quality Verification

### Unit & Integration Test Suite:
`python -m pytest tests/`  
**Result: 32 passed, 33 warnings in 13.85s**
- `tests/test_lookalike_pipeline.py`: 11 passed
  1. Exact legitimate domain (`AUTHENTIC_DOMAIN`)
  2. Normal typosquatting detection
  3. Digit substitution detection
  4. Hyphen manipulation detection
  5. Homoglyph Unicode attack (`HOMOGLYPH_DECEPTION`)
  6. Punycode RFC-3492 attack (`PUNYCODE_IDN_SPOOF`)
  7. Subdomain lure deception (`SUBDOMAIN_LURE`)
  8. Model hash mismatch / integrity failure (Fails closed)
  9. Raw score labeling compliance
  10. Model unavailable fallback handling
  11. FastAPI `/api/v1/emails/lookalike-detect` endpoint verification
- `tests/test_email_pipeline.py`: 3 passed
- `tests/test_enrichment_attribution.py`: 15 passed
- `tests/test_ml_pipeline.py`: 3 passed

### Frontend & Mobile Builds:
- **Web Production Build:** `tsc -b && vite build` $	o$ **Passed in 3.16s** (0 errors).
- **Mobile TypeScript Verification:** `npx tsc --noEmit` $	o$ **Passed with code 0** (0 errors).

---

## 9. Verification of All Frozen Artifact Checksums

| Target Component | Expected SHA-256 | Actual Verified SHA-256 | Status |
|---|---|---|---|
| **Model 1 (`phishing_baseline_v1`)** | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | **MATCH** |
| **Model 2 (`bec_baseline_v1`)** | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` | **MATCH** |
| **IWSPA Independent Test** | `a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552` | `a3b984dba0bb11a939e7a1cd5a2d0b1e19845f1d10f7970aa5557b90de233552` | **MATCH** |
| **ANVESH Challenge 50** | `a5abe63187a59eb32c730ec2dd0f7d248629fd7a50679baaa296bd224092c68f` | `a5abe63187a59eb32c730ec2dd0f7d248629fd7a50679baaa296bd224092c68f` | **MATCH** |
| **Model 3B (`lookalike_domain_v1`)** | `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559` | `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559` | **MATCH** |

---

## 10. Operational Limitations & Boundaries

1. **Not Attacker Attribution:** Model 3B detects lexical and structural proximity between candidate and target domains. It does **NOT** indicate who registered the domain, physical location, or actor attribution.
2. **Not 100% Real-World Detection:** Novel evasion techniques (e.g. newly registered unrelated domain names used in lure campaigns) fall outside lexical lookalike boundaries and are detected by ANVESH's other layers (reputation, SPF/DMARC, behavioral BEC analysis).
3. **Uncalibrated Probabilities:** The numeric score is a raw Random Forest tree vote count. It must not be interpreted as a calibrated real-world likelihood percentage.
4. **Defense-in-Depth Required:** The Random Forest model alone can miss multi-character homoglyphs due to degraded ASCII distance; the Tier 1 deterministic security layer is indispensable.
