"""
ANVESH Model 4 Inference Predictor: 42-Feature Network Intrusion & Relay Anomaly Engine.

Governance Guarantees:
- Model 4 is cryptographically verified (SHA-256: cff24447eea49030ed13777669c0c7c691af8e13db304d9cae657d9b9c2173b1)
- Verifies model integrity at initialization; fails closed on tamper or mismatch.
- Telemetry & network connection evidence only; NEVER asserts actor identity.
- Mandatory Attribution Boundary: "Actor Identity: NOT ESTABLISHED"
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Union
import joblib
import numpy as np

EXPECTED_MODEL_SHA256 = "cff24447eea49030ed13777669c0c7c691af8e13db304d9cae657d9b9c2173b1"
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "network_intrusion_v1"
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "model.joblib"
DEFAULT_METADATA_PATH = DEFAULT_MODEL_DIR / "metadata.json"
DEFAULT_TOP_FEATURES_PATH = DEFAULT_MODEL_DIR / "top_features.json"

FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

NOMINAL_FEATURES = {
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "land": "0",
    "logged_in": "0",
    "is_host_login": "0",
    "is_guest_login": "0"
}


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


class NetworkIntrusionPredictor:
    """Thread-safe inference predictor for the 42-Feature Network Intrusion Engine."""

    def __init__(self, model_path: Path = DEFAULT_MODEL_PATH, verify_integrity: bool = True):
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model 4 artifact missing at: {self.model_path}")

        if verify_integrity:
            actual_sha = compute_sha256(self.model_path)
            if actual_sha != EXPECTED_MODEL_SHA256:
                raise ValueError(
                    f"Model 4 SHA-256 integrity mismatch! Expected {EXPECTED_MODEL_SHA256}, got {actual_sha}."
                )

        self.pipeline = joblib.load(self.model_path)
        self.metadata = {}
        if DEFAULT_METADATA_PATH.exists():
            with open(DEFAULT_METADATA_PATH, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

        self.top_features = []
        if DEFAULT_TOP_FEATURES_PATH.exists():
            with open(DEFAULT_TOP_FEATURES_PATH, "r", encoding="utf-8") as f:
                self.top_features = json.load(f)

    def prepare_vector(self, data: Union[Dict[str, Any], List[Any]]) -> List[Any]:
        """Convert input dict or list into the strict 41-feature ordered vector."""
        if isinstance(data, list):
            if len(data) == len(FEATURE_NAMES):
                return data
            elif len(data) == len(FEATURE_NAMES) + 1:
                return data[:len(FEATURE_NAMES)]
            else:
                raise ValueError(f"Expected {len(FEATURE_NAMES)} features, got {len(data)}.")

        row = []
        for name in FEATURE_NAMES:
            if name in data:
                val = data[name]
            elif name in NOMINAL_FEATURES:
                val = NOMINAL_FEATURES[name]
            else:
                val = 0.0

            if name in NOMINAL_FEATURES:
                row.append(str(val))
            else:
                try:
                    row.append(float(val))
                except (ValueError, TypeError):
                    row.append(0.0)
        return row

    def predict(self, data: Union[Dict[str, Any], List[Any]]) -> Dict[str, Any]:
        """Run inference on the 41-feature vector and output structured forensic findings."""
        vector = self.prepare_vector(data)
        X_arr = np.array([vector], dtype=object)

        pred = int(self.pipeline.predict(X_arr)[0])
        probs = self.pipeline.predict_proba(X_arr)[0]
        anomaly_prob = float(probs[1]) if len(probs) > 1 else float(pred)

        threat_score = int(round(anomaly_prob * 100))

        if threat_score >= 80:
            severity = "CRITICAL"
            confidence = "HIGH"
        elif threat_score >= 60:
            severity = "HIGH"
            confidence = "HIGH"
        elif threat_score >= 40:
            severity = "MEDIUM"
            confidence = "MEDIUM"
        elif threat_score >= 15:
            severity = "LOW"
            confidence = "LOW"
        else:
            severity = "NORMAL"
            confidence = "HIGH"

        # Map top active features for this connection
        active_features = []
        for item in self.top_features[:5]:
            fname = item["feature"]
            idx = FEATURE_NAMES.index(fname)
            val = vector[idx]
            active_features.append({
                "feature": fname,
                "importance": item["importance"],
                "observed_value": val
            })

        return {
            "model_name": "network_intrusion_v1",
            "model_version": "1.0.0",
            "anomaly_detected": bool(pred == 1),
            "threat_score": threat_score,
            "raw_probability": round(anomaly_prob, 4),
            "severity": severity,
            "confidence": confidence,
            "top_contributing_features": active_features,
            "attribution_boundary": "Network & Relay Telemetry Evidence Only; Actor Identity: NOT ESTABLISHED"
        }
