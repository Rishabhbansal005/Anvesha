"""
ANVESH Model 1 Baseline Training & Validation Pipeline.

Architecture:
- Input: Subject + Body
- Preprocessing: Deterministic Text Normalizer & Tokenizer
- Feature Extraction: TF-IDF (1-2 n-grams, 10,000 max features, sublinear TF)
- Classifier: Logistic Regression (C=1.0, class_weight='balanced', random_state=42)
- Target: Binary (0: BENIGN, 1: THREAT_PHISHING)

Governance Rules:
1. Only binary labels (BENIGN, THREAT_PHISHING) used.
2. THREAT_ADVANCE_FEE strictly excluded from training/validation.
3. Held-out corpora (IWSPA-AP, ANVESH Challenge 50) NOT used.
4. Actual metrics calculated and saved; no fabrication.
"""

import datetime
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

# Add workspace root to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from ml.preprocessing.text_cleaner import clean_email_text, normalize_email_pair


def load_jsonl_records(filepath: Path) -> List[Dict]:
    """Load records from a JSONL file."""
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def filter_binary_corpus(records: List[Dict]) -> Tuple[List[Dict], int]:
    """
    Filter records strictly for Model 1 binary classification:
    - Target labels: 'BENIGN' (0), 'THREAT_PHISHING' (1)
    - Excluded labels: 'THREAT_ADVANCE_FEE'
    """
    filtered = []
    excluded_count = 0
    for r in records:
        label = r.get("anvesh_label")
        if label in ("BENIGN", "THREAT_PHISHING"):
            filtered.append(r)
        elif label == "THREAT_ADVANCE_FEE":
            excluded_count += 1
    return filtered, excluded_count


def extract_texts_and_labels(records: List[Dict]) -> Tuple[List[str], np.ndarray]:
    """Extract normalized text (subject + body) and integer target labels."""
    texts = []
    labels = []
    for r in records:
        text = normalize_email_pair(r.get("subject", ""), r.get("body", ""))
        texts.append(text)
        # Binary target: 1 for THREAT_PHISHING, 0 for BENIGN
        labels.append(1 if r["anvesh_label"] == "THREAT_PHISHING" else 0)
    return texts, np.array(labels, dtype=int)


def run_training_pipeline():
    print("=" * 70)
    print("ANVESH — MODEL 1 BASELINE TRAINING & VALIDATION PIPELINE")
    print("=" * 70)

    # 1. Paths
    datasets_dir = WORKSPACE_ROOT / "ml" / "datasets" / "processed"
    train_path = datasets_dir / "train.jsonl"
    val_path = datasets_dir / "val.jsonl"
    output_model_dir = WORKSPACE_ROOT / "ml" / "models" / "phishing_baseline_v1"
    output_model_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading training data from: {train_path}")
    raw_train = load_jsonl_records(train_path)
    print(f"Loading validation data from: {val_path}")
    raw_val = load_jsonl_records(val_path)

    # 2. Filter for Binary Target (Excluding THREAT_ADVANCE_FEE)
    train_records, train_excluded = filter_binary_corpus(raw_train)
    val_records, val_excluded = filter_binary_corpus(raw_val)

    print(f"Raw Train Records: {len(raw_train)} -> Binary Train Records: {len(train_records)} (Excluded THREAT_ADVANCE_FEE: {train_excluded})")
    print(f"Raw Val Records:   {len(raw_val)} -> Binary Val Records:   {len(val_records)} (Excluded THREAT_ADVANCE_FEE: {val_excluded})")

    assert len(train_records) == 6171, f"Expected 6,171 binary train records, found {len(train_records)}"
    assert len(val_records) == 2645, f"Expected 2,645 binary val records, found {len(val_records)}"

    # 3. Text Normalization & Target Extraction
    print("Executing deterministic text normalization (Subject + Body)...")
    X_train, y_train = extract_texts_and_labels(train_records)
    X_val, y_val = extract_texts_and_labels(val_records)

    train_pos = int(np.sum(y_train == 1))
    train_neg = int(np.sum(y_train == 0))
    val_pos = int(np.sum(y_val == 1))
    val_neg = int(np.sum(y_val == 0))

    print(f"Train Label Distribution: THREAT_PHISHING (1) = {train_pos}, BENIGN (0) = {train_neg}")
    print(f"Val Label Distribution:   THREAT_PHISHING (1) = {val_pos}, BENIGN (0) = {val_neg}")

    # 4. Pipeline Construction
    random_seed = 42
    tfidf_config = {
        "ngram_range": (1, 2),
        "max_features": 10000,
        "sublinear_tf": True,
        "token_pattern": r"(?u)\b\w+\b|__\w+__",  # Preserves security tokens
    }
    lr_config = {
        "C": 1.0,
        "class_weight": "balanced",
        "random_state": random_seed,
        "max_iter": 1000,
        "solver": "lbfgs",
    }

    print("\nInitializing Pipeline:")
    print(f"  TfidfVectorizer: {tfidf_config}")
    print(f"  LogisticRegression: {lr_config}")

    vectorizer = TfidfVectorizer(**tfidf_config)
    classifier = LogisticRegression(**lr_config)

    pipeline = Pipeline([
        ("tfidf", vectorizer),
        ("clf", classifier),
    ])

    # 5. Training
    print("\nFitting Model 1 on training set only...")
    start_time = datetime.datetime.now(datetime.timezone.utc)
    pipeline.fit(X_train, y_train)
    end_time = datetime.datetime.now(datetime.timezone.utc)
    print(f"Training completed in {(end_time - start_time).total_seconds():.2f} seconds.")

    # 6. Validation Evaluation
    print("\nEvaluating on Validation Set (2,645 records)...")
    val_proba = pipeline.predict_proba(X_val)
    val_phishing_proba = val_proba[:, 1]
    val_pred = (val_phishing_proba >= 0.5).astype(int)

    # Compute Actual Validation Metrics
    acc = float(accuracy_score(y_val, val_pred))
    prec = float(precision_score(y_val, val_pred, pos_label=1))
    rec = float(recall_score(y_val, val_pred, pos_label=1))
    f1 = float(f1_score(y_val, val_pred, pos_label=1))
    macro_f1 = float(f1_score(y_val, val_pred, average="macro"))
    weighted_f1 = float(f1_score(y_val, val_pred, average="weighted"))
    roc_auc = float(roc_auc_score(y_val, val_phishing_proba))

    cm = confusion_matrix(y_val, val_pred)
    tn, fp, fn, tp = [int(x) for x in cm.ravel()]

    print("\n" + "=" * 50)
    print("ACTUAL VALIDATION METRICS (Threshold = 0.50):")
    print("=" * 50)
    print(f"  Accuracy:       {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision:      {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall:         {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1-Score:       {f1:.4f} ({f1*100:.2f}%)")
    print(f"  Macro F1:       {macro_f1:.4f}")
    print(f"  Weighted F1:    {weighted_f1:.4f}")
    print(f"  ROC-AUC:        {roc_auc:.4f}")
    print("\nConfusion Matrix:")
    print(f"  True Positives (TP):  {tp}")
    print(f"  True Negatives (TN):  {tn}")
    print(f"  False Positives (FP): {fp}")
    print(f"  False Negatives (FN): {fn}")
    print(f"  Total Evaluated:      {tp + tn + fp + fn}")

    # 7. Threshold Tradeoff Analysis (Validation Set Only)
    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    threshold_tradeoffs = []
    print("\nThreshold Tradeoff Analysis (Validation Set):")
    print(f"  {'Threshold':<10} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'FP Count':<10} {'FN Count':<10}")
    for t in thresholds:
        t_pred = (val_phishing_proba >= t).astype(int)
        t_prec = float(precision_score(y_val, t_pred, pos_label=1, zero_division=0))
        t_rec = float(recall_score(y_val, t_pred, pos_label=1, zero_division=0))
        t_f1 = float(f1_score(y_val, t_pred, pos_label=1, zero_division=0))
        t_cm = confusion_matrix(y_val, t_pred)
        t_tn, t_fp, t_fn, t_tp = [int(x) for x in t_cm.ravel()]
        threshold_tradeoffs.append({
            "threshold": t,
            "precision": round(t_prec, 4),
            "recall": round(t_rec, 4),
            "f1_score": round(t_f1, 4),
            "false_positives": t_fp,
            "false_negatives": t_fn,
        })
        print(f"  {t:<10.2f} {t_prec:<12.4f} {t_rec:<12.4f} {t_f1:<12.4f} {t_fp:<10} {t_fn:<10}")

    # 8. Feature Explainability (Top 30 Positive & Negative Features)
    feature_names = vectorizer.get_feature_names_out()
    coefs = classifier.coef_[0]

    top_pos_indices = np.argsort(coefs)[-30:][::-1]
    top_neg_indices = np.argsort(coefs)[:30]

    top_positive_features = [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4), "association": "THREAT_PHISHING"}
        for i in top_pos_indices
    ]
    top_negative_features = [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4), "association": "BENIGN"}
        for i in top_neg_indices
    ]

    print("\nTop 10 Phishing Statistical Model Features (Positive Coefficients):")
    for item in top_positive_features[:10]:
        print(f"  {item['feature']:<30} (weight: +{item['weight']:.4f})")

    print("\nTop 10 Benign Statistical Model Features (Negative Coefficients):")
    for item in top_negative_features[:10]:
        print(f"  {item['feature']:<30} (weight: {item['weight']:.4f})")

    # 9. Model Artifact Serialization
    model_file = output_model_dir / "model.joblib"
    metadata_file = output_model_dir / "metadata.json"
    top_features_file = output_model_dir / "top_features.json"

    print(f"\nSaving model artifact to: {model_file}")
    joblib.dump(pipeline, model_file)

    top_features_data = {
        "description": "Top statistical model features extracted from Logistic Regression coefficients. These represent empirical vocabulary correlations learned from training and must not be interpreted as causal explanations.",
        "top_positive_features_phishing": top_positive_features,
        "top_negative_features_benign": top_negative_features,
    }
    with open(top_features_file, "w", encoding="utf-8") as f:
        json.dump(top_features_data, f, indent=2)

    metadata = {
        "model_name": "anvesh_phishing_baseline",
        "model_version": "1.0.0",
        "model_type": "TF-IDF + Logistic Regression Binary Classifier",
        "training_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "random_seed": random_seed,
        "dataset_manifest_version": "1.1.0",
        "dataset_counts": {
            "training_samples": len(train_records),
            "validation_samples": len(val_records),
            "train_phishing_count": train_pos,
            "train_benign_count": train_neg,
            "val_phishing_count": val_pos,
            "val_benign_count": val_neg,
            "threat_advance_fee_excluded_from_fit": train_excluded + val_excluded,
            "held_out_iwspa_test_count": 3000,
            "held_out_challenge_count": 50,
        },
        "label_mapping": {
            "0": "BENIGN",
            "1": "THREAT_PHISHING"
        },
        "preprocessing_configuration": {
            "unicode_normalization": "NFKC",
            "html_unescape": True,
            "html_strip_tags": True,
            "url_tokenization": "__URL_TOKEN__",
            "email_tokenization": "__EMAIL_TOKEN__",
            "currency_tokenization": "__CURRENCY_TOKEN__",
            "mime_artifact_strip": True,
            "whitespace_normalization": True
        },
        "vectorizer_hyperparameters": tfidf_config,
        "classifier_hyperparameters": lr_config,
        "actual_validation_metrics": {
            "threshold_evaluated": 0.5,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "total": tp + tn + fp + fn
            }
        },
        "threshold_tradeoff_analysis": threshold_tradeoffs,
        "software_environment": {
            "python_version": sys.version.split()[0],
            "scikit_learn_version": sklearn.__version__,
            "joblib_version": joblib.__version__,
            "numpy_version": np.__version__
        },
        "governance_guarantees": {
            "probability_calibration_status": "UNAVAILABLE_RAW_MODEL_PROBABILITIES (Calibration not yet performed)",
            "iwspa_test_isolation": "100% untouched and held-out",
            "anvesh_challenge_isolation": "100% untouched and held-out",
            "actor_attribution_capability": "NOT ESTABLISHED (Model 1 does not infer actor identity or causal intent)"
        },
        "known_limitations": [
            "Pure text classifier without visibility into SPF, DKIM, DMARC, IP reputation, DNS, or domain WHOIS.",
            "Historical email vocabulary may require domain-adaptation for emerging SaaS MFA spoofing techniques.",
            "Probability outputs represent raw logistic sigmoid values, not calibrated Bayesian posteriors."
        ]
    }

    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Metadata saved to: {metadata_file}")
    print(f"Top features saved to: {top_features_file}")
    print("\nModel 1 Baseline Training & Validation Complete.")
    print("=" * 70)


if __name__ == "__main__":
    run_training_pipeline()
