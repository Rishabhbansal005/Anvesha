"""
ANVESH Source-Aware Evaluation Pipeline.

Measures out-of-source generalization across different benign corpora within the development set:
- Experiment A: Train on Enron (Benign) + Phishing -> Evaluate on SpamAssassin (Benign) + Phishing
- Experiment B: Train on SpamAssassin (Benign) + Phishing -> Evaluate on Enron (Benign) + Phishing
- Experiment C: Train on Mixed Enron + SpamAssassin (Benign) + Phishing -> Evaluate on Mixed Validation

Governance Directives Enforced:
1. ONLY development corpus (train.jsonl + val.jsonl) accessed.
2. IWSPA-AP (independent_test_iwspa.jsonl) and ANVESH Challenge (anvesh_challenge_50.jsonl) are NEVER loaded or touched.
3. THREAT_ADVANCE_FEE is strictly excluded from binary fitting/evaluation.
4. Production model.joblib is NOT overwritten.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

# Set workspace root
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from ml.preprocessing.text_cleaner import normalize_email_pair

RANDOM_SEED = 42


def load_development_corpus() -> List[Dict[str, Any]]:
    """Load only train.jsonl and val.jsonl from processed datasets directory."""
    datasets_dir = WORKSPACE_ROOT / "ml" / "datasets" / "processed"
    train_path = datasets_dir / "train.jsonl"
    val_path = datasets_dir / "val.jsonl"

    records = []
    for p in (train_path, val_path):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

    # Filter binary target only
    binary_records = [
        r for r in records
        if r.get("anvesh_label") in ("BENIGN", "THREAT_PHISHING")
    ]
    return binary_records


def build_pipeline() -> Pipeline:
    """Build standardized TF-IDF + Logistic Regression pipeline."""
    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=10000,
                sublinear_tf=True,
                token_pattern=r"(?u)\b\w+\b|__\w+__",
            ),
        ),
        (
            "clf",
            LogisticRegression(
                C=1.0,
                class_weight="balanced",
                random_state=RANDOM_SEED,
                max_iter=1000,
                solver="lbfgs",
            ),
        ),
    ])


def evaluate_experiment(
    exp_name: str,
    train_records: List[Dict[str, Any]],
    eval_records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Train and evaluate a specific source-aware experiment."""
    # Preprocess text
    X_train = [
        normalize_email_pair(r.get("subject", ""), r.get("body", ""))
        for r in train_records
    ]
    y_train = np.array(
        [1 if r["anvesh_label"] == "THREAT_PHISHING" else 0 for r in train_records],
        dtype=int,
    )

    X_eval = [
        normalize_email_pair(r.get("subject", ""), r.get("body", ""))
        for r in eval_records
    ]
    y_eval = np.array(
        [1 if r["anvesh_label"] == "THREAT_PHISHING" else 0 for r in eval_records],
        dtype=int,
    )

    # Fit pipeline
    pipe = build_pipeline()
    pipe.fit(X_train, y_train)

    # Predict
    proba = pipe.predict_proba(X_eval)
    p_phish = proba[:, 1]
    preds = (p_phish >= 0.5).astype(int)

    # Metrics
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

    # Probability analysis
    benign_mask = y_eval == 0
    phish_mask = y_eval == 1

    benign_proba = p_phish[benign_mask]
    phish_proba = p_phish[phish_mask]

    near_boundary = int(np.sum((p_phish >= 0.40) & (p_phish <= 0.60)))

    # Per-source analysis
    eval_sources = set(r["source_dataset"] for r in eval_records)
    per_source = {}
    for s in sorted(eval_sources):
        idx = [i for i, r in enumerate(eval_records) if r["source_dataset"] == s]
        s_y = y_eval[idx]
        s_pred = preds[idx]
        s_p = p_phish[idx]
        s_cm = confusion_matrix(s_y, s_pred, labels=[0, 1])
        s_tn, s_fp, s_fn, s_tp = [int(x) for x in s_cm.ravel()]
        per_source[s] = {
            "sample_count": len(idx),
            "true_label": "BENIGN" if all(y == 0 for y in s_y) else ("THREAT_PHISHING" if all(y == 1 for y in s_y) else "MIXED"),
            "accuracy": round(float(accuracy_score(s_y, s_pred)), 4),
            "false_positives": s_fp,
            "false_negatives": s_fn,
            "proba_min": round(float(np.min(s_p)), 4),
            "proba_max": round(float(np.max(s_p)), 4),
            "proba_median": round(float(np.median(s_p)), 4),
            "proba_mean": round(float(np.mean(s_p)), 4),
            "near_boundary_count": int(np.sum((s_p >= 0.40) & (s_p <= 0.60))),
        }

    train_sources_summary = {}
    for r in train_records:
        src = r["source_dataset"]
        train_sources_summary[src] = train_sources_summary.get(src, 0) + 1

    eval_sources_summary = {}
    for r in eval_records:
        src = r["source_dataset"]
        eval_sources_summary[src] = eval_sources_summary.get(src, 0) + 1

    return {
        "experiment_name": exp_name,
        "train_sample_count": len(train_records),
        "eval_sample_count": len(eval_records),
        "train_sources": train_sources_summary,
        "eval_sources": eval_sources_summary,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
            },
            "benign_false_positive_rate": round(benign_fpr, 4),
            "phishing_false_negative_rate": round(phish_fnr, 4),
        },
        "probability_distribution": {
            "overall_min": round(float(np.min(p_phish)), 4),
            "overall_max": round(float(np.max(p_phish)), 4),
            "overall_median": round(float(np.median(p_phish)), 4),
            "benign_median": round(float(np.median(benign_proba)), 4) if len(benign_proba) > 0 else None,
            "benign_mean": round(float(np.mean(benign_proba)), 4) if len(benign_proba) > 0 else None,
            "benign_min": round(float(np.min(benign_proba)), 4) if len(benign_proba) > 0 else None,
            "benign_max": round(float(np.max(benign_proba)), 4) if len(benign_proba) > 0 else None,
            "phishing_median": round(float(np.median(phish_proba)), 4) if len(phish_proba) > 0 else None,
            "phishing_mean": round(float(np.mean(phish_proba)), 4) if len(phish_proba) > 0 else None,
            "phishing_min": round(float(np.min(phish_proba)), 4) if len(phish_proba) > 0 else None,
            "phishing_max": round(float(np.max(phish_proba)), 4) if len(phish_proba) > 0 else None,
            "near_boundary_count": near_boundary,
        },
        "per_source_breakdown": per_source,
    }


def run_all_experiments():
    print("=" * 75)
    print("ANVESH — SOURCE-AWARE EVALUATION PIPELINE (DEVELOPMENT CORPUS ONLY)")
    print("=" * 75)

    all_dev = load_development_corpus()
    print(f"Total Binary Development Samples Loaded: {len(all_dev)}")

    enron = [r for r in all_dev if r["source_dataset"] == "enron_corporate_corpus"]
    spamassassin = [r for r in all_dev if r["source_dataset"] == "spamassassin_public_corpus"]
    phishing = [r for r in all_dev if r["source_dataset"] == "mendeley_nazario_phishing_corpus"]

    print(f"  Enron Benign Records:        {len(enron)}")
    print(f"  SpamAssassin Benign Records: {len(spamassassin)}")
    print(f"  Phishing Records:            {len(phishing)}")

    # Split phishing deterministically 70% / 30%
    np.random.seed(RANDOM_SEED)
    phishing_shuffled = list(phishing)
    np.random.shuffle(phishing_shuffled)
    phish_split_idx = int(0.7 * len(phishing_shuffled))
    phish_train_70 = phishing_shuffled[:phish_split_idx]
    phish_eval_30 = phishing_shuffled[phish_split_idx:]

    print(f"  Phishing Train (70%):        {len(phish_train_70)}")
    print(f"  Phishing Eval (30%):         {len(phish_eval_30)}")

    results = []

    # =========================================================================
    # EXPERIMENT A: Train on Enron + 70% Phishing -> Eval on SpamAssassin + 30% Phishing
    # =========================================================================
    print("\n--- Running Experiment A: Train on Enron + Phishing -> Eval on SpamAssassin + Phishing ---")
    exp_a_train = enron + phish_train_70
    exp_a_eval = spamassassin + phish_eval_30
    res_a = evaluate_experiment("Experiment A (Train: Enron+Phishing | Eval: SpamAssassin+Phishing)", exp_a_train, exp_a_eval)
    results.append(res_a)
    print(f"  Accuracy:  {res_a['metrics']['accuracy']:.4f}")
    print(f"  F1-Score:  {res_a['metrics']['f1_score']:.4f}")
    print(f"  SpamAssassin Benign FP: {res_a['per_source_breakdown']['spamassassin_public_corpus']['false_positives']} / {len(spamassassin)}")
    print(f"  SpamAssassin Median Proba: {res_a['per_source_breakdown']['spamassassin_public_corpus']['proba_median']:.4f} (Mean: {res_a['per_source_breakdown']['spamassassin_public_corpus']['proba_mean']:.4f})")

    # =========================================================================
    # EXPERIMENT B: Train on SpamAssassin + 70% Phishing -> Eval on Enron + 30% Phishing
    # =========================================================================
    print("\n--- Running Experiment B: Train on SpamAssassin + Phishing -> Eval on Enron + Phishing ---")
    exp_b_train = spamassassin + phish_train_70
    exp_b_eval = enron + phish_eval_30
    res_b = evaluate_experiment("Experiment B (Train: SpamAssassin+Phishing | Eval: Enron+Phishing)", exp_b_train, exp_b_eval)
    results.append(res_b)
    print(f"  Accuracy:  {res_b['metrics']['accuracy']:.4f}")
    print(f"  F1-Score:  {res_b['metrics']['f1_score']:.4f}")
    print(f"  Enron Benign FP: {res_b['per_source_breakdown']['enron_corporate_corpus']['false_positives']} / {len(enron)}")
    print(f"  Enron Median Proba: {res_b['per_source_breakdown']['enron_corporate_corpus']['proba_median']:.4f} (Mean: {res_b['per_source_breakdown']['enron_corporate_corpus']['proba_mean']:.4f})")

    # =========================================================================
    # EXPERIMENT C: Train on Mixed Enron + SpamAssassin (70%) + Phishing (70%) -> Eval on 30% Mixed
    # =========================================================================
    print("\n--- Running Experiment C: Train on Both Benign Sources (70%) -> Eval on Mixed Val (30%) ---")
    np.random.seed(RANDOM_SEED)
    enron_shuffled = list(enron)
    np.random.shuffle(enron_shuffled)
    enron_split = int(0.7 * len(enron_shuffled))
    enron_tr = enron_shuffled[:enron_split]
    enron_ev = enron_shuffled[enron_split:]

    sa_shuffled = list(spamassassin)
    np.random.shuffle(sa_shuffled)
    sa_split = int(0.7 * len(sa_shuffled))
    sa_tr = sa_shuffled[:sa_split]
    sa_ev = sa_shuffled[sa_split:]

    exp_c_train = enron_tr + sa_tr + phish_train_70
    exp_c_eval = enron_ev + sa_ev + phish_eval_30
    res_c = evaluate_experiment("Experiment C (Train: Mixed Enron+SpamAssassin+Phishing | Eval: Mixed Val)", exp_c_train, exp_c_eval)
    results.append(res_c)
    print(f"  Accuracy:  {res_c['metrics']['accuracy']:.4f}")
    print(f"  F1-Score:  {res_c['metrics']['f1_score']:.4f}")
    print(f"  Mixed Val FP: {res_c['metrics']['confusion_matrix']['false_positives']}, FN: {res_c['metrics']['confusion_matrix']['false_negatives']}")
    print(f"  Enron Sub-Val Median Proba: {res_c['per_source_breakdown']['enron_corporate_corpus']['proba_median']:.4f}")
    print(f"  SpamAssassin Sub-Val Median Proba: {res_c['per_source_breakdown']['spamassassin_public_corpus']['proba_median']:.4f}")

    # Output JSON results
    out_dir = WORKSPACE_ROOT / "ml" / "evaluation"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "source_aware_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "evaluation_pipeline_version": "1.0.0",
                "evaluated_at": "2026-09-06T15:20:00Z",
                "governance_guarantees": {
                    "iwspa_test_accessed": False,
                    "anvesh_challenge_accessed": False,
                    "model_joblib_overwritten": False,
                    "hyperparameters_tuned": False,
                },
                "experiments": results,
            },
            f,
            indent=2,
        )
    print(f"\nMachine-readable results saved to: {json_path}")
    print("=" * 75)
    return results


if __name__ == "__main__":
    run_all_experiments()
