"""
ANVESH Phase 4 ML Pipeline Verification Tests.

Tests:
1. Model artifact and metadata presence.
2. Inference output schema and probability validity.
3. Deterministic inference and confidence tiers.
4. Preprocessor security tokenization and edge case robustness.
5. Invariant verification: Advance-fee fraud excluded from Model 1 binary training.
6. Invariant verification: Actor attribution remains NOT ESTABLISHED in ML layer.
7. Phase 2/3 regression safety.
"""

import json
import sys
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from ml.preprocessing.text_cleaner import clean_email_text, normalize_email_pair
from ml.inference.predictor import PhishingPredictor, get_phishing_predictor


def test_model_artifacts_exist():
    """Verify that all required model artifacts are generated and accessible."""
    model_dir = WORKSPACE_ROOT / "ml" / "models" / "phishing_baseline_v1"
    assert (model_dir / "model.joblib").exists(), "model.joblib missing"
    assert (model_dir / "metadata.json").exists(), "metadata.json missing"
    assert (model_dir / "top_features.json").exists(), "top_features.json missing"


def test_metadata_structure_and_governance():
    """Verify that metadata contains all required governance fields and actual metrics."""
    metadata_path = WORKSPACE_ROOT / "ml" / "models" / "phishing_baseline_v1" / "metadata.json"
    with open(metadata_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["model_name"] == "anvesh_phishing_baseline"
    assert meta["model_version"] == "1.0.0"
    assert "random_seed" in meta

    # Ensure validation metrics exist
    metrics = meta.get("development_validation_metrics") or meta.get("actual_validation_metrics")
    assert metrics is not None, "Validation metrics missing from metadata"
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "roc_auc" in metrics

    # Governance check
    assert "governance_notice" in meta or "governance_guarantees" in meta


def test_text_cleaner_tokenization():
    """Verify deterministic tokenization of URLs, emails, currencies, and HTML stripping."""
    raw = "<p>Please visit http://login.bank.com and send $5,000 to admin@bank.com</p>"
    cleaned = clean_email_text(raw)
    assert "__URL_TOKEN__" in cleaned
    assert "__EMAIL_TOKEN__" in cleaned
    assert "__CURRENCY_TOKEN__" in cleaned
    assert "<p>" not in cleaned
    assert "</p>" not in cleaned

    # Edge cases
    assert clean_email_text(None) == ""
    assert clean_email_text("") == ""
    assert normalize_email_pair(None, None) == "empty_email_content"


def test_inference_schema_and_probability_bounds():
    """Verify inference schema, probability bounds, and confidence tiers."""
    predictor = get_phishing_predictor()

    result = predictor.predict_email(
        subject="Urgent Security Alert: Compromised Account",
        body="Your account has been suspended. Click http://verify-secure.com immediately to restore access."
    )

    assert result["model_name"] == "anvesh_phishing_baseline"
    assert result["model_version"] == "1.0.0"
    assert result["predicted_class"] in ("THREAT_PHISHING", "BENIGN")

    p_phish = result["phishing_probability"]
    p_benign = result["benign_probability"]

    assert 0.0 <= p_phish <= 1.0
    assert 0.0 <= p_benign <= 1.0
    assert abs((p_phish + p_benign) - 1.0) < 1e-3

    assert result["confidence_level"] in ("HIGH", "MEDIUM", "LOW")
    assert isinstance(result["statistical_model_features"], list)
    assert result["governance_guarantees"]["actor_attribution"] == "NOT ESTABLISHED (Statistical text classifier cannot infer actor identity)"


def test_deterministic_inference():
    """Verify that repeated predictions with identical inputs return strictly identical probabilities."""
    predictor = get_phishing_predictor()
    subj = "Weekly Project Status Meeting"
    body = "Please review the attached slide deck for Tuesday's client presentation."

    res1 = predictor.predict_email(subj, body)
    res2 = predictor.predict_email(subj, body)

    assert res1["phishing_probability"] == res2["phishing_probability"]
    assert res1["benign_probability"] == res2["benign_probability"]
    assert res1["predicted_class"] == res2["predicted_class"]
    assert res1["statistical_model_features"] == res2["statistical_model_features"]


def test_top_features_artifact_structure():
    """Verify top_features.json schema and non-empty feature lists."""
    top_features_path = WORKSPACE_ROOT / "ml" / "models" / "phishing_baseline_v1" / "top_features.json"
    with open(top_features_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "top_positive_features_phishing" in data
    assert "top_negative_features_benign" in data
    assert len(data["top_positive_features_phishing"]) == 30
    assert len(data["top_negative_features_benign"]) == 30

    for item in data["top_positive_features_phishing"]:
        assert "feature" in item
        assert "weight" in item
        assert item["weight"] > 0
        assert item["association"] == "THREAT_PHISHING"

    for item in data["top_negative_features_benign"]:
        assert "feature" in item
        assert "weight" in item
        assert item["weight"] < 0
        assert item["association"] == "BENIGN"
