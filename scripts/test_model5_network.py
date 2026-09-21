import requests
import json

url = "http://localhost:8000/api/v1/network/analyze"

print("="*60)
print("TEST 1: NORMAL BENIGN NETWORK CONNECTION (Regular web browsing)")
print("="*60)
benign_payload = {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "src_bytes": 235,
    "dst_bytes": 1250,
    "count": 2,
    "serror_rate": 0.0,
    "same_srv_rate": 1.0
}
res1 = requests.post(url, json=benign_payload).json()
print("Anomaly Detected:", res1.get("anomaly_detected"))
print("Threat Score:", res1.get("threat_score"), "/ 100")
print("Severity:", res1.get("severity"))
print("Confidence:", res1.get("confidence"))

print("\n" + "="*60)
print("TEST 2: MALICIOUS ATTACK CONNECTION (SYN Flood & Port Scanning)")
print("="*60)
attack_payload = {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "private",
    "flag": "S0",
    "src_bytes": 0,
    "dst_bytes": 0,
    "count": 320,
    "serror_rate": 1.0,
    "srv_serror_rate": 1.0,
    "dst_host_count": 255,
    "dst_host_srv_count": 3,
    "dst_host_serror_rate": 1.0
}
res2 = requests.post(url, json=attack_payload).json()
print("Anomaly Detected:", res2.get("anomaly_detected"))
print("Threat Score:", res2.get("threat_score"), "/ 100")
print("Severity:", res2.get("severity"))
print("Confidence:", res2.get("confidence"))
print("Top Contributing Features:")
for feat in res2.get("top_contributing_features", []):
    print(f"  * {feat.get('feature')}: observed={feat.get('observed_value')}, weight={feat.get('importance'):.3f}")
print("\nAttribution Boundary:", res2.get("attribution_boundary"))
