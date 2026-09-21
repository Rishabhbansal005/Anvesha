"""
ANVESH Model 3B Standalone Inference Predictor.
Encapsulates Lookalike Domain / Brand Impersonation Detection.
Combines Tier 1 Deterministic Security Invariants with Tier 2 Random Forest Structural Model.

Governance Guarantees:
- Model 3B is FROZEN (SHA-256: 31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559)
- Verifies model integrity at initialization; FAILS CLOSED on mismatch
- Tier 1 Deterministic Invariants (Homoglyph, Punycode, Subdomain Lure) are authoritative
  and CANNOT be overridden by low ML probabilities
- Returns uncalibrated raw model scores, NEVER calibrated probability claims
- Infrastructure and domain evidence only; NEVER asserts actor identity
"""

import os
import re
import math
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
import joblib
import numpy as np

EXPECTED_MODEL_SHA256 = "31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559"
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "lookalike_domain_v1"
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "model.joblib"
DEFAULT_METADATA_PATH = DEFAULT_MODEL_DIR / "metadata.json"

FEATURE_NAMES = [
    "levenshtein_distance",
    "normalized_edit_distance",
    "jaro_winkler",
    "length_diff",
    "tld_match",
    "has_homoglyph",
    "is_punycode",
    "digit_substitution_count",
    "hyphen_count_diff",
    "brand_in_subdomain"
]


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    max_dist = math.floor(max(len1, len2) / 2) - 1
    match1 = [False] * len1
    match2 = [False] * len2
    matches = 0
    for i in range(len1):
        start = max(0, i - max_dist)
        end = min(i + max_dist + 1, len2)
        for j in range(start, end):
            if match2[j] or s1[i] != s2[j]:
                continue
            match1[i] = True
            match2[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    transpositions = 0
    k = 0
    for i in range(len1):
        if not match1[i]:
            continue
        while not match2[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    t = transpositions / 2
    jaro = (matches / len1 + matches / len2 + (matches - t) / matches) / 3
    prefix = 0
    for c1, c2 in zip(s1[:4], s2[:4]):
        if c1 == c2:
            prefix += 1
        else:
            break
    return round(jaro + prefix * 0.1 * (1.0 - jaro), 4)


class ModelIntegrityError(Exception):
    """Raised when Model 3B artifact hash does not match the frozen governance invariant."""
    pass


class LookalikePredictor:
    """
    Tiered Lookalike Domain Detection Engine.
    Tier 1: Deterministic Security Invariants.
    Tier 2: Random Forest Structural Model (model.joblib).
    """

    def __init__(self, model_path: Optional[Path] = None, metadata_path: Optional[Path] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.metadata_path = metadata_path or DEFAULT_METADATA_PATH
        self.model = None
        self.metadata = {}
        self.is_loaded = False
        self._load_and_verify()

    def _load_and_verify(self):
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model 3B artifact missing at {self.model_path}")

        # Compute SHA-256 hash
        h = hashlib.sha256()
        with open(self.model_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        actual_hash = h.hexdigest()

        if actual_hash != EXPECTED_MODEL_SHA256:
            raise ModelIntegrityError(
                f"Model 3B hash mismatch! Expected {EXPECTED_MODEL_SHA256}, got {actual_hash}. "
                f"Governance rule violated: Failing closed."
            )

        self.model = joblib.load(self.model_path)
        if self.metadata_path.exists():
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
        self.is_loaded = True

    def extract_features(self, trusted_domain: str, candidate_domain: str) -> Dict[str, float]:
        t_clean = trusted_domain.lower().strip()
        c_clean = candidate_domain.lower().strip()

        t_parts = t_clean.split(".")
        c_parts = c_clean.split(".")

        t_sld = t_parts[0] if t_parts else ""
        c_sld = c_parts[0] if c_parts else ""

        t_tld = t_parts[-1] if len(t_parts) > 1 else ""
        c_tld = c_parts[-1] if len(c_parts) > 1 else ""

        lev = levenshtein_distance(t_sld, c_sld)
        max_len = max(len(t_sld), len(c_sld))
        norm_lev = round(lev / max_len, 4) if max_len > 0 else 0.0
        jw = jaro_winkler_similarity(t_sld, c_sld)

        has_homoglyph = 1 if any(ord(c) > 127 for c in c_clean) else 0
        is_punycode = 1 if (c_clean.startswith("xn--") or ".xn--" in c_clean) else 0

        digit_subs = len(re.findall(r"[0135]", c_sld))
        hyphen_diff = abs(c_sld.count("-") - t_sld.count("-"))
        tld_match = 1 if (t_tld and c_tld and t_tld == c_tld) else 0

        brand_slug = t_sld
        is_exact_authentic = (c_clean == t_clean or c_clean.endswith("." + t_clean))
        brand_in_subdomain = 1 if ((brand_slug in c_clean or t_clean in c_clean) and not is_exact_authentic) else 0
        len_diff = abs(len(t_clean) - len(c_clean))

        return {
            "levenshtein_distance": float(lev),
            "normalized_edit_distance": float(norm_lev),
            "jaro_winkler": float(jw),
            "length_diff": float(len_diff),
            "tld_match": float(tld_match),
            "has_homoglyph": float(has_homoglyph),
            "is_punycode": float(is_punycode),
            "digit_substitution_count": float(digit_subs),
            "hyphen_count_diff": float(hyphen_diff),
            "brand_in_subdomain": float(brand_in_subdomain)
        }

    def predict(self, trusted_domain: str, candidate_domain: str) -> Dict[str, Any]:
        """
        Execute tiered inference:
        Tier 1: Deterministic Security Invariants
        Tier 2: Random Forest Structural Model
        """
        if not self.is_loaded:
            raise RuntimeError("Model 3B predictor is not loaded or has failed integrity checks.")

        t_clean = trusted_domain.lower().strip()
        c_clean = candidate_domain.lower().strip()

        features = self.extract_features(t_clean, c_clean)
        deterministic_indicators = []
        explanation = []

        is_exact_authentic = (c_clean == t_clean or c_clean.endswith("." + t_clean))

        # Tier 1: Deterministic Invariants
        if features["has_homoglyph"] == 1.0:
            deterministic_indicators.append("HOMOGLYPH_DECEPTION")
            explanation.append("Non-ASCII homoglyph Unicode characters observed in candidate domain.")

        if features["is_punycode"] == 1.0:
            deterministic_indicators.append("PUNYCODE_IDN_SPOOF")
            explanation.append("RFC-3492 Punycode (xn--) internationalized domain encoding observed.")

        if features["brand_in_subdomain"] == 1.0 and not is_exact_authentic:
            deterministic_indicators.append("SUBDOMAIN_LURE")
            explanation.append(f"Trusted brand '{t_clean}' prepended as deceptive subdomain lure on external host.")

        # If domain is authentic identical and no spoofing indicator
        if is_exact_authentic and not deterministic_indicators:
            return {
                "model": "lookalike_domain_v1",
                "signal": "NONE",
                "raw_model_score": 0.0,
                "deterministic_indicators": ["AUTHENTIC_DOMAIN"],
                "features": features,
                "explanation": ["Candidate domain matches trusted infrastructure or legitimate subdomain."],
                "model_status": "FROZEN"
            }

        # Tier 2: Random Forest Inference
        feat_vector = np.array([[features[fn] for fn in FEATURE_NAMES]])
        rf_score = float(self.model.predict_proba(feat_vector)[0, 1])

        # Add ML structural explanations
        if features["normalized_edit_distance"] <= 0.25 and features["normalized_edit_distance"] > 0:
            explanation.append(f"High lexical proximity detected (Normalized edit distance: {features['normalized_edit_distance']:.2f}).")
        if features["jaro_winkler"] >= 0.85:
            explanation.append(f"Visual and phonetic resemblance detected (Jaro-Winkler: {features['jaro_winkler']:.2f}).")
        if features["digit_substitution_count"] > 0:
            explanation.append(f"Leet-speak digit substitution observed ({int(features['digit_substitution_count'])} substitutions).")
        if features["tld_match"] == 0.0 and (features["jaro_winkler"] >= 0.80 or features["normalized_edit_distance"] <= 0.30):
            explanation.append("Top-level domain (TLD) substitution detected against trusted brand.")

        # Hard invariant: Deterministic indicators guarantee HIGH signal
        if deterministic_indicators:
            signal = "HIGH"
        elif rf_score >= 0.70:
            signal = "HIGH"
        elif rf_score >= 0.45:
            signal = "MEDIUM"
        elif rf_score >= 0.20:
            signal = "LOW"
        else:
            signal = "NONE"

        return {
            "model": "lookalike_domain_v1",
            "signal": signal,
            "raw_model_score": round(rf_score, 4),
            "deterministic_indicators": deterministic_indicators,
            "features": features,
            "explanation": explanation,
            "model_status": "FROZEN"
        }


_predictor_instance: Optional[LookalikePredictor] = None


def get_lookalike_predictor() -> LookalikePredictor:
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = LookalikePredictor()
    return _predictor_instance
