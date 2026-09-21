"""
ANVESH Backend Network Intrusion & Telemetry Evidence Service.
Integrates Model 4 (network_intrusion_v1: 42-Feature Network Telemetry Engine) into ANVESH.
Provides network session scoring, mail relay forensic evaluation, and threat detection.
"""

import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Union

_repo_root = str(Path(__file__).resolve().parent.parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from ml.inference.network_intrusion_predictor import NetworkIntrusionPredictor

logger = logging.getLogger("ANVESH.NetworkIntrusionService")


class NetworkIntrusionService:
    def __init__(self):
        try:
            self.predictor = NetworkIntrusionPredictor(verify_integrity=True)
            self.available = True
            logger.info("[NETWORK_INTRUSION] Model 4 initialized successfully with verified SHA-256 signature.")
        except Exception as e:
            logger.error(f"[NETWORK_INTRUSION] Failed to initialize Model 4: {e}")
            self.predictor = None
            self.available = False

    def analyze_telemetry(self, telemetry_data: Union[Dict[str, Any], List[Any]]) -> Dict[str, Any]:
        """Analyze a 41-feature network telemetry connection payload."""
        if not self.available or self.predictor is None:
            return {
                "model_name": "network_intrusion_v1",
                "model_version": "1.0.0",
                "anomaly_detected": False,
                "threat_score": 0,
                "raw_probability": 0.0,
                "severity": "UNAVAILABLE",
                "confidence": "NONE",
                "top_contributing_features": [],
                "error": "Model 4 service unavailable"
            }
        return self.predictor.predict(telemetry_data)

    def analyze_mail_relay(self, service: str = "smtp", src_bytes: float = 0.0, dst_bytes: float = 0.0, duration: float = 0.0) -> Dict[str, Any]:
        """Convenience method for analyzing email transport connections (e.g. SMTP on port 25 or POP3)."""
        payload = {
            "service": service,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "duration": duration,
            "protocol_type": "tcp",
            "flag": "SF"
        }
        return self.analyze_telemetry(payload)


_network_service_instance = None


def get_network_intrusion_service() -> NetworkIntrusionService:
    global _network_service_instance
    if _network_service_instance is None:
        _network_service_instance = NetworkIntrusionService()
    return _network_service_instance
