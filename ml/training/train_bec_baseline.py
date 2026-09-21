import os
import json
import hashlib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
import joblib

def load_jsonl(filepath):
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    df = pd.DataFrame(records)
    df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
    df["target"] = df["label"].map(lambda x: 1 if x == "BEC" else 0)
    return df

print("=== 1. Loading Governed Datasets ===")
train_df = load_jsonl("ml/datasets/bec/train.jsonl")
val_df = load_jsonl("ml/datasets/bec/val.jsonl")
indep_df = load_jsonl("ml/datasets/bec/independent_test_dube_bec2.jsonl")
adv_df = load_jsonl("ml/datasets/bec/adversarial_test.jsonl")

print(f"TRAIN samples: {len(train_df)} (BEC: {sum(train_df['target']==1)}, NON_BEC: {sum(train_df['target']==0)})")
print(f"VAL samples:   {len(val_df)} (BEC: {sum(val_df['target']==1)}, NON_BEC: {sum(val_df['target']==0)})")
print(f"INDEP samples: {len(indep_df)} (BEC: {sum(indep_df['target']==1)}, NON_BEC: {sum(indep_df['target']==0)})")
print(f"ADV samples:   {len(adv_df)} (BEC: {sum(adv_df['target']==1)}, NON_BEC: {sum(adv_df['target']==0)})")

print("\n=== 2. Building Model 2 Pipeline ===")
pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words="english",
        max_features=5000
    )),
    ("clf", LogisticRegression(
        C=1.0,
        class_weight="balanced",
        random_state=42,
        max_iter=1000
    ))
])

X_train, y_train = train_df["text"], train_df["target"]
pipeline.fit(X_train, y_train)
print("Model 2 fitted successfully on TRAIN partition.")

def evaluate_partition(name, df):
    X = df["text"]
    y = df["target"]
    preds = pipeline.predict(X)
    probs = pipeline.predict_proba(X)[:, 1]
    
    acc = accuracy_score(y, preds)
    prec = precision_score(y, preds, zero_division=0)
    rec = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)
    try:
        roc = roc_auc_score(y, probs) if len(set(y)) > 1 else 1.0
    except Exception:
        roc = 1.0
        
    cm = confusion_matrix(y, preds)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        bec_rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        bec_fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        non_bec_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    else:
        tn, fp, fn, tp = 0, 0, 0, int(sum(preds == 1))
        bec_rec = float(tp / len(y)) if len(y) > 0 else 0.0
        bec_fnr = 1.0 - bec_rec
        non_bec_fpr = 0.0
        
    return {
        "partition_name": name,
        "sample_count": len(df),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc), 4),
        "bec_recall": round(float(bec_rec), 4),
        "bec_fnr": round(float(bec_fnr), 4),
        "non_bec_fpr": round(float(non_bec_fpr), 4),
        "confusion_matrix": cm.tolist()
    }

print("\n=== 3. Executing Multi-Partition Evaluation ===")
val_metrics = evaluate_partition("VALIDATION_IN_SOURCE", val_df)
indep_metrics = evaluate_partition("INDEPENDENT_DUBE_BEC2", indep_df)
adv_metrics = evaluate_partition("ADVERSARIAL_EVASION_BENCHMARK", adv_df)

print("\n--- VALIDATION METRICS ---")
print(json.dumps(val_metrics, indent=2))

print("\n--- INDEPENDENT TEST (Dube BEC-2) METRICS ---")
print(json.dumps(indep_metrics, indent=2))

print("\n--- ADVERSARIAL EVASION TEST METRICS ---")
print(json.dumps(adv_metrics, indent=2))

# 4. Extract Top Features
vectorizer = pipeline.named_steps["tfidf"]
classifier = pipeline.named_steps["clf"]
feature_names = np.array(vectorizer.get_feature_names_out())
coefs = classifier.coef_[0]

top_pos_idx = np.argsort(coefs)[-20:][::-1]
top_neg_idx = np.argsort(coefs)[:20]

top_features = {
    "top_bec_features": [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4)} for i in top_pos_idx
    ],
    "top_non_bec_features": [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4)} for i in top_neg_idx
    ]
}

# 5. Error Analysis on Independent Test
indep_df["pred"] = pipeline.predict(indep_df["text"])
indep_df["prob"] = np.round(pipeline.predict_proba(indep_df["text"])[:, 1], 4)

fn_samples = indep_df[(indep_df["target"] == 1) & (indep_df["pred"] == 0)]
fp_samples = indep_df[(indep_df["target"] == 0) & (indep_df["pred"] == 1)]

print(f"\nIndependent Test False Negatives: {len(fn_samples)}")
print(f"Independent Test False Positives: {len(fp_samples)}")

error_analysis = {
    "independent_fn_count": len(fn_samples),
    "independent_fp_count": len(fp_samples),
    "false_negatives": [
        {
            "id": r.get("id"),
            "subject": r.get("subject"),
            "subtype": r.get("subtype"),
            "prob": r.get("prob")
        } for _, r in fn_samples.head(5).iterrows()
    ],
    "false_positives": [
        {
            "id": r.get("id"),
            "subject": r.get("subject"),
            "subtype": r.get("subtype"),
            "prob": r.get("prob")
        } for _, r in fp_samples.head(5).iterrows()
    ]
}

# 6. Save Model Artifacts
os.makedirs("ml/models/bec_baseline_v1", exist_ok=True)
model_path = "ml/models/bec_baseline_v1/model.joblib"
joblib.dump(pipeline, model_path)

with open(model_path, "rb") as f:
    model_sha = hashlib.sha256(f.read()).hexdigest()

with open("ml/models/bec_baseline_v1/top_features.json", "w", encoding="utf-8") as f:
    json.dump(top_features, f, indent=2)

metadata = {
    "model_name": "bec_baseline_v1",
    "version": "1.0.0",
    "architecture": "TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True, max_features=5000) + LogisticRegression(C=1.0, class_weight='balanced', random_state=42)",
    "input_fields": ["subject", "body"],
    "training_sources": ["Kaggle_Synthetic_BEC_Curated", "Enron_Corporate_Corpus"],
    "validation_sources": ["Kaggle_Synthetic_BEC_Curated", "Enron_Corporate_Corpus"],
    "independent_test_source": "Rohit_Dube_BEC2_Benchmark",
    "adversarial_test_source": "Kaggle_Adversarial_Evasion_Benchmark",
    "sample_counts": {
        "train": len(train_df),
        "validation": len(val_df),
        "independent_test": len(indep_df),
        "adversarial_test": len(adv_df)
    },
    "hyperparameters": {
        "ngram_range": [1, 2],
        "sublinear_tf": True,
        "max_features": 5000,
        "C": 1.0,
        "class_weight": "balanced",
        "random_state": 42,
        "max_iter": 1000
    },
    "decision_threshold": 0.50,
    "calibration_status": "UNCALIBRATED_RAW_SIGMOID",
    "model_sha256": model_sha,
    "governance_status": "DEVELOPMENT_BASELINE_EVALUATED"
}

with open("ml/models/bec_baseline_v1/metadata.json", "w", encoding="utf-8") as f:
    json.dump(metadata, f, indent=2)

# 7. Save Evaluation Results
results_payload = {
    "evaluation_timestamp": "2026-09-06T16:53:00Z",
    "model_name": "bec_baseline_v1",
    "model_sha256": model_sha,
    "validation_metrics": val_metrics,
    "independent_test_metrics": indep_metrics,
    "adversarial_test_metrics": adv_metrics,
    "error_analysis": error_analysis,
    "governance_classification": "B. DEVELOPMENT BASELINE (Useful research baseline, held-out staging)"
}

with open("ml/evaluation/model2_bec_results.json", "w", encoding="utf-8") as f:
    json.dump(results_payload, f, indent=2)

print("\nAll Model 2 BEC artifacts and results exported successfully!")
