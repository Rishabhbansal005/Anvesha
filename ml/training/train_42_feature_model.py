"""
ANVESH — Model 4 Training Pipeline: 42-Feature Network Intrusion Detection
Trained on: KDDTest+.arff (with stratified train/validation split)
Evaluated on: KDDTest-21.arff (Hard/Adversarial 21-model failure holdout)
Uses 100% standard scikit-learn Pipeline and ColumnTransformer for universal portability.
"""
import os
import json
import hashlib
from datetime import datetime, timezone
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

TRAIN_ARFF = r"C:\Users\Ongkar\Downloads\KDDTest+.arff"
HARD_TEST_ARFF = r"C:\Users\Ongkar\Downloads\KDDTest-21.arff"
OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "network_intrusion_v1"))

def parse_arff(file_path):
    print(f"[*] Reading ARFF file: {file_path}")
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        
    attributes = []
    data_rows = []
    is_data = False
    
    for line in lines:
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("%") or cleaned.lower().startswith("@relation"):
            continue
        if cleaned.lower().startswith("@attribute"):
            parts = cleaned.split(None, 2)
            attr_name = parts[1].strip("'\"")
            attr_type = parts[2].strip()
            attributes.append((attr_name, attr_type))
            continue
        if cleaned.lower().startswith("@data"):
            is_data = True
            continue
        if is_data:
            cols = [c.strip().strip("'\"") for c in cleaned.split(",")]
            if len(cols) == len(attributes):
                data_rows.append(cols)
                
    attr_names = [a[0] for a in attributes]
    feature_names = attr_names[:-1]
    
    nominal_indices = []
    numeric_indices = []
    
    for i, (name, atype) in enumerate(attributes[:-1]):
        if "{" in atype:
            nominal_indices.append(i)
        else:
            numeric_indices.append(i)
            
    nominal_cols = [attr_names[i] for i in nominal_indices]
    numeric_cols = [attr_names[i] for i in numeric_indices]
    
    X_rows = []
    y_list = []
    for row in data_rows:
        row_vals = []
        for i in range(len(feature_names)):
            if i in numeric_indices:
                try:
                    row_vals.append(float(row[i]))
                except ValueError:
                    row_vals.append(0.0)
            else:
                row_vals.append(str(row[i]))
        X_rows.append(row_vals)
        y_list.append(1 if row[-1] == "anomaly" else 0)
        
    return feature_names, nominal_cols, numeric_cols, nominal_indices, numeric_indices, np.array(X_rows, dtype=object), np.array(y_list, dtype=int)

def calculate_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def train_and_evaluate():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 1. Parse datasets
    feat_names, nom_cols, num_cols, nom_idx, num_idx, X_full, y_full = parse_arff(TRAIN_ARFF)
    _, _, _, _, _, X_hard, y_hard = parse_arff(HARD_TEST_ARFF)
    
    print(f"[+] Total Primary Records: {len(X_full)} | Features: {len(feat_names)}")
    print(f"[+] Total Hard Test Records: {len(X_hard)}")
    
    # 2. Stratified Split (80% Train / 20% Validation)
    X_train, X_val, y_train, y_val = train_test_split(
        X_full, y_full, test_size=0.20, random_state=42, stratify=y_full
    )
    print(f"[+] Train split: {len(X_train)} samples | Val split: {len(X_val)} samples")
    
    # 3. Standard Pipeline with ColumnTransformer
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), nom_idx),
            ("num", StandardScaler(), num_idx)
        ]
    )
    
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    
    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", clf)
    ])
    
    print("[*] Training Pipeline on 42-feature schema...")
    pipeline.fit(X_train, y_train)
    print("[+] Model training completed.")
    
    # 4. Evaluate Validation Set
    val_preds = pipeline.predict(X_val)
    val_probs = pipeline.predict_proba(X_val)[:, 1]
    
    val_metrics = {
        "accuracy": round(float(accuracy_score(y_val, val_preds)), 4),
        "precision": round(float(precision_score(y_val, val_preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_val, val_preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_val, val_preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_val, val_probs)), 4),
        "confusion_matrix": confusion_matrix(y_val, val_preds).tolist()
    }
    print(f"[+] Validation: Acc={val_metrics['accuracy']}, F1={val_metrics['f1']}, AUC={val_metrics['roc_auc']}")
    
    # 5. Evaluate Hard Test Set (KDDTest-21)
    hard_preds = pipeline.predict(X_hard)
    hard_probs = pipeline.predict_proba(X_hard)[:, 1]
    
    hard_metrics = {
        "accuracy": round(float(accuracy_score(y_hard, hard_preds)), 4),
        "precision": round(float(precision_score(y_hard, hard_preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_hard, hard_preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_hard, hard_preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_hard, hard_probs)), 4),
        "confusion_matrix": confusion_matrix(y_hard, hard_preds).tolist()
    }
    print(f"[+] KDDTest-21 Hard Holdout: Acc={hard_metrics['accuracy']}, F1={hard_metrics['f1']}, AUC={hard_metrics['roc_auc']}")
    
    # 6. Feature Importances
    fitted_preprocessor = pipeline.named_steps["preprocessor"]
    fitted_clf = pipeline.named_steps["classifier"]
    
    cat_feature_names = fitted_preprocessor.named_transformers_["cat"].get_feature_names_out().tolist()
    all_transformed_feature_names = cat_feature_names + num_cols
    importances = fitted_clf.feature_importances_
    
    agg_importance = {name: 0.0 for name in feat_names}
    for t_name, imp in zip(all_transformed_feature_names, importances):
        if t_name.startswith("x"):
            prefix = t_name.split("_")[0] # e.g. x0, x1
            try:
                orig_idx = nom_idx[int(prefix[1:])]
                orig_name = feat_names[orig_idx]
                agg_importance[orig_name] += float(imp)
            except Exception:
                pass
        else:
            if t_name in agg_importance:
                agg_importance[t_name] += float(imp)
                
    sorted_top_features = [
        {"feature": k, "importance": round(v, 4)}
        for k, v in sorted(agg_importance.items(), key=lambda x: x[1], reverse=True)
    ]
    
    # 7. Save Pipeline Directly (No custom classes, 100% portable)
    model_path = os.path.join(OUTPUT_DIR, "model.joblib")
    joblib.dump(pipeline, model_path, compress=3)
    print(f"[+] Standalone pipeline saved to {model_path}")
    
    top_features_path = os.path.join(OUTPUT_DIR, "top_features.json")
    with open(top_features_path, "w", encoding="utf-8") as f:
        json.dump(sorted_top_features, f, indent=2)
        
    metadata = {
        "model_name": "network_intrusion_v1",
        "model_version": "1.0.0",
        "model_type": "RandomForestClassifier",
        "framework": "scikit-learn",
        "task": "NETWORK_INTRUSION_AND_RELAY_ANOMALY_DETECTION",
        "features_count": len(feat_names),
        "feature_names": feat_names,
        "nominal_features": nom_cols,
        "numeric_features": num_cols,
        "nominal_indices": nom_idx,
        "numeric_indices": num_idx,
        "training_date": datetime.now(timezone.utc).isoformat(),
        "random_seed": 42,
        "model_sha256": calculate_sha256(model_path),
        "validation_metrics": val_metrics,
        "hard_adversarial_metrics_kdd21": hard_metrics,
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 16,
            "class_weight": "balanced",
            "random_state": 42
        }
    }
    
    metadata_path = os.path.join(OUTPUT_DIR, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Metadata written to {metadata_path}")

if __name__ == "__main__":
    train_and_evaluate()
