"""
ANVESH — Enhanced Model 1 Training & Calibration Pipeline
Ingests Zenodo Benchmark + User Lures Dataset (package, banking, gift card, payment declined)
Trains TF-IDF (1-2 n-grams) + Logistic Regression classifier with class balancing.
Outputs serialized model to ml/models/phishing_baseline_v1/model.joblib
"""
import csv
import json
import hashlib
from pathlib import Path
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
import sys
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from ml.preprocessing.text_cleaner import normalize_email_pair

def load_jsonl_records(filepath: Path):
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records

def load_user_lures(filepath: Path):
    samples = []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = (row.get("Email Text") or "").strip()
            label_str = (row.get("Email Type") or "").strip().lower()
            if not text:
                continue
            label = 1 if "phish" in label_str else 0
            samples.append((text, label))
    return samples

def main():
    print("=" * 70)
    print("ANVESH ENHANCED MODEL 1 TRAINING PIPELINE")
    print("=" * 70)

    # 1. Load Base Corpora
    train_path = WORKSPACE_ROOT / "ml" / "datasets" / "processed" / "train.jsonl"
    val_path = WORKSPACE_ROOT / "ml" / "datasets" / "processed" / "val.jsonl"
    lures_path = WORKSPACE_ROOT / "ml" / "datasets" / "user_lures_dataset.csv"

    print("Loading base training & validation sets...")
    base_train = load_jsonl_records(train_path)
    base_val = load_jsonl_records(val_path)

    X_train = []
    y_train = []
    for r in base_train:
        if r.get("anvesh_label") in ("BENIGN", "THREAT_PHISHING"):
            norm_text = normalize_email_pair(r.get("subject", ""), r.get("body", ""))
            X_train.append(norm_text)
            y_train.append(1 if r["anvesh_label"] == "THREAT_PHISHING" else 0)

    X_val = []
    y_val = []
    for r in base_val:
        if r.get("anvesh_label") in ("BENIGN", "THREAT_PHISHING"):
            norm_text = normalize_email_pair(r.get("subject", ""), r.get("body", ""))
            X_val.append(norm_text)
            y_val.append(1 if r["anvesh_label"] == "THREAT_PHISHING" else 0)

    print(f"Base Training Records: {len(X_train)} (Pos: {sum(y_train)}, Neg: {len(y_train)-sum(y_train)})")
    print(f"Base Validation Records: {len(X_val)} (Pos: {sum(y_val)}, Neg: {len(y_val)-sum(y_val)})")

    # 2. Ingest User Lures Dataset
    if lures_path.exists():
        lures = load_user_lures(lures_path)
        print(f"Loaded User Lures Samples: {len(lures)}")
        # 70/30 split of lures into train/val
        np.random.seed(42)
        indices = np.random.permutation(len(lures))
        split_idx = int(0.7 * len(lures))
        train_lures_idx = indices[:split_idx]
        val_lures_idx = indices[split_idx:]

        for i in train_lures_idx:
            text, lbl = lures[i]
            X_train.append(text.lower())
            y_train.append(lbl)

        for i in val_lures_idx:
            text, lbl = lures[i]
            X_val.append(text.lower())
            y_val.append(lbl)

    print(f"Total Enhanced Training Samples: {len(X_train)}")
    print(f"Total Enhanced Validation Samples: {len(X_val)}")

    y_train_arr = np.array(y_train, dtype=int)
    y_val_arr = np.array(y_val, dtype=int)

    # 3. Construct TF-IDF + Logistic Regression Pipeline
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=12000,
            sublinear_tf=True,
            token_pattern=r"(?u)\b\w+\b|__\w+__|[$]\d+"
        )),
        ("classifier", LogisticRegression(
            C=1.5,
            class_weight="balanced",
            max_iter=1000,
            random_state=42
        ))
    ])

    print("Fitting Enhanced Pipeline...")
    pipeline.fit(X_train, y_train_arr)

    # 4. Evaluate on Validation Set
    val_preds = pipeline.predict(X_val)
    val_probs = pipeline.predict_proba(X_val)[:, 1]

    acc = accuracy_score(y_val_arr, val_preds)
    prec = precision_score(y_val_arr, val_preds)
    rec = recall_score(y_val_arr, val_preds)
    f1 = f1_score(y_val_arr, val_preds)
    roc = roc_auc_score(y_val_arr, val_probs)
    tn, fp, fn, tp = confusion_matrix(y_val_arr, val_preds).ravel()
    fpr = fp / (fp + tn)

    print("\n" + "=" * 50)
    print("VALIDATION BENCHMARK RESULTS")
    print("=" * 50)
    print(f"Accuracy:            {acc * 100:.2f}%")
    print(f"Precision:           {prec * 100:.2f}%")
    print(f"Recall:              {rec * 100:.2f}%")
    print(f"F1-Score:            {f1 * 100:.2f}%")
    print(f"ROC-AUC:             {roc * 100:.2f}%")
    print(f"False Positive Rate: {fpr * 100:.2f}% (TN={tn}, FP={fp}, FN={fn}, TP={tp})")

    # 5. Serialize Model
    model_dir = WORKSPACE_ROOT / "ml" / "models" / "phishing_baseline_v1"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_file = model_dir / "model.joblib"
    joblib.dump(pipeline, model_file, compress=3)

    # Compute SHA-256
    with open(model_file, "rb") as f:
        model_sha256 = hashlib.sha256(f.read()).hexdigest()

    meta_file = model_dir / "metadata.json"
    metadata = {
        "model_name": "anvesh_phishing_enhanced",
        "version": "2.0.0",
        "trained_date": "2026-09-19",
        "sha256": model_sha256,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc, 4),
            "false_positive_rate": round(fpr, 4)
        },
        "dataset_manifest": {
            "total_train": len(X_train),
            "total_val": len(X_val),
            "user_lures_included": True,
            "corpora": ["Zenodo_IEEE2024_Nazario", "Enron", "CEAS", "User_Lures_Corpus"]
        }
    }
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nModel successfully serialized to: {model_file}")
    print(f"Model SHA-256: {model_sha256}")
    print(f"Metadata saved to: {meta_file}")

if __name__ == "__main__":
    main()
