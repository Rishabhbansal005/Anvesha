"""
ANVESH Model 1 Standalone Inference Predictor.
Encapsulates TF-IDF + Logistic Regression inference, probability estimation, and local feature attribution.

Governance Guarantees:
- Pure text classification (Subject + Body)
- Returns uncalibrated model probability estimates (no 'calibrated' claims)
- Never infers or asserts actor identity
- Exposes top active statistical tokens for the input
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from ml.preprocessing.text_cleaner import normalize_email_pair

# Default artifact paths
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "phishing_baseline_v1"
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "model.joblib"
DEFAULT_METADATA_PATH = DEFAULT_MODEL_DIR / "metadata.json"


class PhishingPredictor:
    """
    Production-ready inference engine for Model 1 (TF-IDF + Logistic Regression).
    """

    def __init__(self, model_path: Optional[Path] = None, metadata_path: Optional[Path] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.metadata_path = metadata_path or DEFAULT_METADATA_PATH
        self.pipeline = None
        self.metadata = {}
        self.model_name = "anvesh_phishing_baseline"
        self.model_version = "1.0.0"
        self._load_artifacts()

    def _load_artifacts(self):
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at: {self.model_path}")

        self.pipeline = joblib.load(self.model_path)

        if self.metadata_path.exists():
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
                self.model_name = self.metadata.get("model_name", self.model_name)
                self.model_version = self.metadata.get("model_version", self.model_version)

    def predict_email(self, subject: Optional[str], body: Optional[str]) -> Dict[str, Any]:
        """
        Run inference on an email subject and body.

        Args:
            subject: Raw email subject string.
            body: Raw email body string.

        Returns:
            Dictionary containing prediction class, probabilities, confidence, and active statistical features.
        """
        if self.pipeline is None:
            self._load_artifacts()

        # 1. Deterministic text normalization
        clean_text = normalize_email_pair(subject, body)

        # 2. Extract probabilities
        proba_matrix = self.pipeline.predict_proba([clean_text])
        benign_proba = float(proba_matrix[0, 0])
        phishing_proba = float(proba_matrix[0, 1])

        # 3. Class decision (Threshold = 0.5)
        predicted_class = "THREAT_PHISHING" if phishing_proba >= 0.5 else "BENIGN"

        # 4. Confidence tier assignment
        if phishing_proba >= 0.85 or phishing_proba <= 0.15:
            confidence_level = "HIGH"
        elif (phishing_proba >= 0.65) or (phishing_proba <= 0.35):
            confidence_level = "MEDIUM"
        else:
            confidence_level = "LOW"

        # 5. Extract active statistical tokens present in the input
        active_features = self._explain_instance(clean_text)

        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "predicted_class": predicted_class,
            "phishing_probability": round(phishing_proba, 4),
            "benign_probability": round(benign_proba, 4),
            "confidence_level": confidence_level,
            "statistical_model_features": active_features,
            "governance_guarantees": {
                "probability_calibration_status": "RAW_MODEL_PROBABILITY_ESTIMATES (Not calibrated)",
                "actor_attribution": "NOT ESTABLISHED (Statistical text classifier cannot infer actor identity)"
            }
        }

    def _explain_instance(self, clean_text: str) -> List[Dict[str, Any]]:
        """Extract top active features from the input text sorted by absolute logistic weight."""
        try:
            vectorizer = self.pipeline.named_steps["tfidf"]
            classifier = self.pipeline.named_steps["clf"]

            # Transform single instance
            vec = vectorizer.transform([clean_text])
            feature_names = vectorizer.get_feature_names_out()
            coefs = classifier.coef_[0]

            # Find active non-zero feature indices
            nonzero_indices = vec.indices
            if len(nonzero_indices) == 0:
                return []

            # Gather active features with their model coefficients
            active = []
            for idx in nonzero_indices:
                w = float(coefs[idx])
                assoc = "THREAT_PHISHING" if w > 0 else "BENIGN"
                active.append({
                    "feature": str(feature_names[idx]),
                    "weight": round(w, 4),
                    "association": assoc
                })

            # Sort by absolute weight descending (top 10 most impactful features for this email)
            active.sort(key=lambda x: abs(x["weight"]), reverse=True)
            return active[:10]
        except Exception:
            return []


# Module-level singleton
_PREDICTOR_INSTANCE: Optional[PhishingPredictor] = None


def get_phishing_predictor() -> PhishingPredictor:
    """Retrieve or initialize the singleton PhishingPredictor instance."""
    global _PREDICTOR_INSTANCE
    if _PREDICTOR_INSTANCE is None:
        _PREDICTOR_INSTANCE = PhishingPredictor()
    return _PREDICTOR_INSTANCE
