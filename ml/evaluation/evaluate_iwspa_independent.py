"""
ANVESH IWSPA-AP Independent Test Evaluation Pipeline.

Evaluates the frozen production Model 1 artifact ONCE on the 100% held-out
IWSPA-AP Independent Test Set (3,000 samples).

Governance Safeguards:
1. Pure evaluation only. Zero .fit(), .fit_transform(), tuning, or calibration.
2. Cryptographic SHA-256 pre- and post-hashes verify model.joblib and dataset integrity.
3. Input strictly restricted to (subject, body). No headers, auth status, IOCs, or metadata.
4. ANVESH Challenge benchmark (anvesh_challenge_50.jsonl) is strictly NOT accessed.
"""

import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Set workspace root
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from ml.preprocessing.text_cleaner import normalize_email_pair


def compute_sha256(filepath: Path) -> str:
    """Compute cryptographic SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def load_iwspa_dataset(filepath: Path) -> List[Dict[str, Any]]:
    """Load records strictly from the IWSPA-AP JSONL file."""
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def run_iwspa_independent_evaluation():
    print("=" * 75)
    print("ANVESH — IWSPA-AP INDEPENDENT TEST EVALUATION")
    print("=" * 75)

    evaluation_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    iwspa_path = WORKSPACE_ROOT / "ml" / "datasets" / "processed" / "independent_test_iwspa.jsonl"
    model_path = WORKSPACE_ROOT / "ml" / "models" / "phishing_baseline_v1" / "model.joblib"
    metadata_path = WORKSPACE_ROOT / "ml" / "models" / "phishing_baseline_v1" / "metadata.json"

    # 1. Cryptographic Pre-Evaluation Hashing
    assert iwspa_path.exists(), f"IWSPA dataset not found at: {iwspa_path}"
    assert model_path.exists(), f"Model artifact not found at: {model_path}"

    iwspa_pre_hash = compute_sha256(iwspa_path)
    model_pre_hash = compute_sha256(model_path)

    print(f"Evaluation Timestamp: {evaluation_timestamp}")
    print(f"IWSPA Dataset Path:   {iwspa_path}")
    print(f"  Pre-Eval SHA-256:   {iwspa_pre_hash}")
    print(f"Model Artifact Path:  {model_path}")
    print(f"  Pre-Eval SHA-256:   {model_pre_hash}")

    # 2. Dataset Loading & Validation
    records = load_iwspa_dataset(iwspa_path)
    total_samples = len(records)
    print(f"\nLoaded {total_samples:,} independent evaluation records.")

    benign_count = sum(1 for r in records if r.get("anvesh_label") == "BENIGN")
    phishing_count = sum(1 for r in records if r.get("anvesh_label") == "THREAT_PHISHING")

    print(f"  BENIGN Samples:          {benign_count:,}")
    print(f"  THREAT_PHISHING Samples: {phishing_count:,}")

    # Strict validation check
    if benign_count != 1500 or phishing_count != 1500 or total_samples != 3000:
        raise ValueError(
            f"Expected exactly 1,500 BENIGN and 1,500 THREAT_PHISHING (3,000 total). Found: BENIGN={benign_count}, PHISHING={phishing_count}, TOTAL={total_samples}"
        )

    # 3. Source Audit
    sources = {}
    for r in records:
        src = r.get("source_dataset", "unknown")
        sources[src] = sources.get(src, 0) + 1
    print(f"  Source Dataset Distribution: {sources}")

    # 4. Model Loading (Inference Mode Only — Zero Fitting)
    print("\nLoading frozen production Model 1 pipeline...")
    pipeline = joblib.load(model_path)

    # 5. Text Normalization & Feature Preparation
    print("Executing deterministic text normalization (Subject + Body)...")
    X_eval = [
        normalize_email_pair(r.get("subject", ""), r.get("body", ""))
        for r in records
    ]
    y_eval = np.array(
        [1 if r["anvesh_label"] == "THREAT_PHISHING" else 0 for r in records],
        dtype=int,
    )

    # 6. Evaluation Inference (Zero .fit() Calls)
    print("Running batch inference across 3,000 independent samples...")
    proba = pipeline.predict_proba(X_eval)
    p_phish = proba[:, 1]
    p_benign = proba[:, 0]
    preds = (p_phish >= 0.5).astype(int)

    # 7. Metrics Calculation
    acc = float(accuracy_score(y_eval, preds))
    prec = float(precision_score(y_eval, preds, pos_label=1, zero_division=0))
    rec = float(recall_score(y_eval, preds, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_eval, preds, pos_label=1, zero_division=0))
    roc_auc = float(roc_auc_score(y_eval, p_phish))

    cm = confusion_matrix(y_eval, preds)
    tn, fp, fn, tp = [int(x) for x in cm.ravel()]

    benign_total = tn + fp
    phish_total = tp + fn

    benign_fpr = float(fp / benign_total) if benign_total > 0 else 0.0
    phish_fnr = float(fn / phish_total) if phish_total > 0 else 0.0
    benign_specificity = float(tn / benign_total) if benign_total > 0 else 0.0
    phish_recall = float(tp / phish_total) if phish_total > 0 else 0.0

    # 8. Probability Analysis
    benign_mask = y_eval == 0
    phish_mask = y_eval == 1

    benign_proba = p_phish[benign_mask]
    phish_proba = p_phish[phish_mask]

    bins = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.00001]
    b_hist, _ = np.histogram(benign_proba, bins=bins)
    p_hist, _ = np.histogram(phish_proba, bins=bins)
    bin_labels = [
        "0.00-0.10", "0.10-0.20", "0.20-0.30", "0.30-0.40", "0.40-0.50",
        "0.50-0.60", "0.60-0.70", "0.70-0.80", "0.80-0.90", "0.90-1.00"
    ]
    prob_bins_summary = {
        lbl: {"actual_benign": int(b_c), "actual_phishing": int(p_c), "total": int(b_c + p_c)}
        for lbl, b_c, p_c in zip(bin_labels, b_hist, p_hist)
    }

    near_boundary = int(np.sum((p_phish >= 0.40) & (p_phish <= 0.60)))

    # 9. Post-Evaluation Hashing & Integrity Verification
    iwspa_post_hash = compute_sha256(iwspa_path)
    model_post_hash = compute_sha256(model_path)

    assert iwspa_pre_hash == iwspa_post_hash, "CRITICAL: IWSPA dataset file hash changed during evaluation!"
    assert model_pre_hash == model_post_hash, "CRITICAL: Model artifact file hash changed during evaluation!"

    print("\n" + "=" * 50)
    print("IWSPA-AP INDEPENDENT EVALUATION RESULTS")
    print("=" * 50)
    print(f"  Accuracy:            {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Phishing Precision:  {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Phishing Recall:     {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1-Score:            {f1:.4f} ({f1*100:.2f}%)")
    print(f"  ROC-AUC:             {roc_auc:.4f}")
    print("\nConfusion Matrix:")
    print(f"  True Positives (TP):  {tp}")
    print(f"  True Negatives (TN):  {tn}")
    print(f"  False Positives (FP): {fp} (Benign FPR: {benign_fpr*100:.2f}%)")
    print(f"  False Negatives (FN): {fn} (Phishing FNR: {phish_fnr*100:.2f}%)")
    print(f"  Benign Specificity:   {benign_specificity*100:.2f}%")
    print(f"  Phishing Recall:      {phish_recall*100:.2f}%")

    print("\nProbability Distribution Analysis:")
    print(f"  Overall Min:    {np.min(p_phish):.4f}")
    print(f"  Overall Max:    {np.max(p_phish):.4f}")
    print(f"  Overall Median: {np.median(p_phish):.4f}")
    print(f"  Overall Mean:   {np.mean(p_phish):.4f}")
    print(f"  Benign Subset:   Min={np.min(benign_proba):.4f}, Max={np.max(benign_proba):.4f}, Median={np.median(benign_proba):.4f}, Mean={np.mean(benign_proba):.4f}")
    print(f"  Phishing Subset: Min={np.min(phish_proba):.4f}, Max={np.max(phish_proba):.4f}, Median={np.median(phish_proba):.4f}, Mean={np.mean(phish_proba):.4f}")
    print(f"  Samples in [0.40, 0.60] Decision Boundary: {near_boundary}")

    print("\nProbability Bin Histogram:")
    for lbl, b_c, p_c in zip(bin_labels, b_hist, p_hist):
        print(f"  {lbl}: Benign = {b_c:<5} | Phishing = {p_c:<5} | Total = {b_c+p_c:<5}")

    # 10. Save Machine-Readable JSON Results
    out_dir = WORKSPACE_ROOT / "ml" / "evaluation"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "iwspa_independent_results.json"

    results_data = {
        "evaluation_name": "IWSPA-AP Independent Benchmark Evaluation",
        "evaluated_at": evaluation_timestamp,
        "dataset_metadata": {
            "file": "ml/datasets/processed/independent_test_iwspa.jsonl",
            "sha256_hash": iwspa_post_hash,
            "total_samples": total_samples,
            "benign_samples": benign_count,
            "phishing_samples": phishing_count,
            "source_distribution": sources,
        },
        "model_metadata": {
            "model_path": "ml/models/phishing_baseline_v1/model.joblib",
            "model_sha256": model_post_hash,
            "model_name": "anvesh_phishing_baseline",
            "model_version": "1.0.0",
        },
        "overall_metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "benign_specificity": round(benign_specificity, 4),
            "phishing_recall": round(phish_recall, 4),
            "benign_false_positive_rate": round(benign_fpr, 4),
            "phishing_false_negative_rate": round(phish_fnr, 4),
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "total_evaluated": total_samples,
            },
        },
        "probability_distribution": {
            "overall_min": round(float(np.min(p_phish)), 4),
            "overall_max": round(float(np.max(p_phish)), 4),
            "overall_median": round(float(np.median(p_phish)), 4),
            "overall_mean": round(float(np.mean(p_phish)), 4),
            "benign_median": round(float(np.median(benign_proba)), 4),
            "benign_mean": round(float(np.mean(benign_proba)), 4),
            "benign_min": round(float(np.min(benign_proba)), 4),
            "benign_max": round(float(np.max(benign_proba)), 4),
            "phishing_median": round(float(np.median(phish_proba)), 4),
            "phishing_mean": round(float(np.mean(phish_proba)), 4),
            "phishing_min": round(float(np.min(phish_proba)), 4),
            "phishing_max": round(float(np.max(phish_proba)), 4),
            "near_boundary_count": near_boundary,
            "bins": prob_bins_summary,
        },
        "governance_safeguards": {
            "evaluation_mode": "FROZEN_MODEL_SINGLE_PASS_INFERENCE",
            "fitting_calls_made": 0,
            "hyperparameter_tuning_performed": False,
            "threshold_tuning_performed": False,
            "anvesh_challenge_accessed": False,
            "model_file_integrity_preserved": True,
            "dataset_file_integrity_preserved": True,
        },
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results_data, f, indent=2)

    print(f"\nMachine-readable results saved to: {json_path}")
    print("=" * 75)
    return results_data


if __name__ == "__main__":
    run_iwspa_independent_evaluation()
