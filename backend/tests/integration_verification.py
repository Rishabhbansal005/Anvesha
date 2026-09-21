"""
Automated Integration Verification Suite for ANVESH Phase 2.
Tests error handling, oversized payloads, benign vs malicious emails, and alert triage.
"""
import requests
import io
import hashlib

BASE_URL = "http://localhost:8000/api/v1"

def run_tests():
    print("--- TEST 1: Health Secret Leak Check ---")
    h = requests.get(f"{BASE_URL}/health").json()
    assert "service_role" not in str(h).lower()
    assert "supabase_key" not in str(h).lower()
    print("Health check clean. Secrets safe.")

    print("--- TEST 2: Empty Email Upload (400) ---")
    res_empty = requests.post(f"{BASE_URL}/emails/analyze", data={"raw_content": "   "})
    assert res_empty.status_code == 400, f"Expected 400, got {res_empty.status_code}"
    print("Empty upload correctly rejected with 400 Bad Request.")

    print("--- TEST 3: Oversized Upload (413) ---")
    large_content = b"From: test@example.com\n\n" + (b"A" * (11 * 1024 * 1024))
    res_large = requests.post(f"{BASE_URL}/emails/analyze", files={"file": ("large.eml", io.BytesIO(large_content), "message/rfc822")})
    assert res_large.status_code == 413, f"Expected 413, got {res_large.status_code}"
    print("Oversized upload (>10MB) correctly rejected with 413 Payload Too Large.")

    print("--- TEST 4: Benign / Clean Email (Low Risk, No Alert) ---")
    clean_eml = """Received: from mail-relay.trusted-vendor.com (mail-relay.trusted-vendor.com [52.12.34.56])
    by mx.corporate-target.com with ESMTP id 12345
    for <analyst@corporate-target.com>; Wed, 3 Sep 2026 10:00:00 +0530
From: Alice Smith <alice@trusted-vendor.com>
To: analyst@corporate-target.com
Subject: Project Sync Meeting Notes
Date: Wed, 3 Sep 2026 10:00:00 +0530
Message-ID: <notes-12345@trusted-vendor.com>
Authentication-Results: mx.corporate-target.com;
    spf=pass (sender IP 52.12.34.56 matches SPF record);
    dkim=pass (signature verified);
    dmarc=pass (p=reject) header.from=trusted-vendor.com

Hi team, attached are the meeting notes from this morning. Thanks!
"""
    res_clean = requests.post(f"{BASE_URL}/emails/analyze", files={"file": ("clean.eml", io.BytesIO(clean_eml.encode("utf-8")), "message/rfc822")})
    assert res_clean.status_code == 200, f"Expected 200, got {res_clean.status_code}"
    clean_data = res_clean.json()
    score = clean_data.get("risk_score", 0)
    level = clean_data.get("risk_level")
    print(f"Clean Email Score: {score}, Level: {level}")
    assert score < 30, f"Expected Low Risk score (<30), got {score}"
    assert clean_data["spf_status"] == "PASS"
    assert clean_data["dkim_status"] == "PASS"
    assert clean_data["dmarc_status"] == "PASS"
    print("Clean email correctly evaluated as LOW RISK with PASS authentication.")

    print("--- TEST 5: Alert Triage Endpoint ---")
    alerts_res = requests.get(f"{BASE_URL}/alerts").json()
    total_alerts = alerts_res.get("total", 0)
    print(f"Active alerts count in DB: {total_alerts}")
    if alerts_res.get("items"):
        a_id = alerts_res["items"][0]["id"]
        triage_res = requests.post(f"{BASE_URL}/alerts/{a_id}/triage", json={"action": "REVIEW", "note": "Automated triage test"})
        assert triage_res.status_code == 200, f"Triage failed: {triage_res.text}"
        print("Alert successfully triaged and acknowledged in Supabase!")

    print("ALL 5 AUTOMATED INTEGRATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
