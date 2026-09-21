import asyncio
import os
import sys

# Ensure backend path is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi import Request
from app.api.v1.endpoints.emails import analyze_email
from unittest.mock import AsyncMock

async def test_demo_email():
    desktop_eml = os.path.expanduser(r"~\Desktop\ANVESH_ULTIMATE_DEMO.eml")
    with open(desktop_eml, "rb") as f:
        file_bytes = f.read()

    # Create mock UploadFile
    mock_file = AsyncMock()
    mock_file.filename = "ANVESH_ULTIMATE_DEMO.eml"
    mock_file.read = AsyncMock(return_value=file_bytes)

    # Mock request
    mock_request = AsyncMock(spec=Request)
    mock_request.headers = {"content-type": "multipart/form-data"}

    result = await analyze_email(request=mock_request, file=mock_file)

    print("=" * 60)
    print("CASE NUMBER:", result.get("case_number"))
    print("TOTAL RISK SCORE:", result.get("risk_score"))
    print("RISK LEVEL:", result.get("risk_level"))
    print("SENDER:", result.get("sender"))
    print("SUBJECT:", result.get("subject"))
    print("SPF:", result.get("spf_status"))
    print("DKIM:", result.get("dkim_status"))
    print("DMARC:", result.get("dmarc_status"))
    print("PROBABLE ORIGIN IP:", result.get("probable_origin_ip"))
    print("ORIGIN CONFIDENCE:", result.get("origin_confidence"))
    print("LOCATION:", result.get("approximate_location"))
    print("-" * 60)
    print("CATEGORY SCORES (CARDS IN WORKSPACE):")
    cat_scores = result.get("category_scores", {})
    for cat, val in cat_scores.items():
        print(f"  {cat}: {val['score']} / {val['max']}")
    print("-" * 60)
    print("LOOKALIKE EVIDENCE:")
    la = result.get("lookalike_evidence", {})
    print(f"  Signal: {la.get('signal')}, Target: {la.get('trusted_domain')}, Candidate: {la.get('candidate_domain')}")
    print("-" * 60)
    print("IDENTITY IMPERSONATION:")
    ii = result.get("identity_impersonation", {})
    print(f"  Detected: {ii.get('identity_impersonation_detected')}, Confidence: {ii.get('confidence')}, Score: {ii.get('identity_impersonation_score')}")
    print("-" * 60)
    print("INFRASTRUCTURE INTEL:")
    infra = result.get("infrastructure", {})
    print(f"  Country: {infra.get('country')}, City: {infra.get('city')}, ASN: {infra.get('asn')}")
    print(f"  TOR/VPN: {infra.get('vpn_tor_proxy_indicator')}, Abuse Score: {infra.get('reputation_score')}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_demo_email())
