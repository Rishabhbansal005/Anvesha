import urllib.request
import json

test_email = """Received: from mail-relay.evasion-drop.net (mail-relay.evasion-drop.net [185.220.101.5])
    by mx.corporate-target.com with ESMTP id 84HF928FJA
    for <cfo@target-corp.com>; Wed, 09 Sep 2026 01:45:00 +0530
Received: from unknown (HELO internal-c2.shadow-network.org) ([194.26.29.112])
    by mail-relay.evasion-drop.net with SMTP; Wed, 09 Sep 2026 01:44:50 +0530
From: "Satya Nadella (CEO Office)" <exec-alert@micr0soft-security-update.com>
To: "Chief Financial Officer" <cfo@target-corp.com>
Reply-To: "Shadow Operations" <wire-dept@external-shadow-account.ru>
Return-Path: <bounce@evasion-drop.net>
Subject: URGENT: Executive Wire Transfer & Immediate Account Verification Required
Date: Wed, 09 Sep 2026 01:45:00 +0530
Message-ID: <92847291847.20260909@micr0soft-security-update.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

URGENT AND STRICTLY CONFIDENTIAL - EXECUTIVE ACTION REQUIRED

Dear Finance Team,

I am currently in an executive board acquisition meeting with investors and my phone is on silent. 
We have finalized the emergency acquisition of our new European cloud provider. 

1. Please process an immediate wire transfer of $84,500.00 USD to the designated acquisition escrow account before 5:00 PM today.
2. Failure to execute this transaction today will breach our binding purchase contract. Do not discuss this with other staff until public announcement.

Additionally, our corporate Microsoft 365 executive credentials have been flagged for suspension.
Please verify your identity and authorize the transfer immediately by clicking below:
https://login.micr0soft-security-update.com/auth/login.php?user=cfo@target-corp.com

Confirm once the funds have been dispatched.

Regards,
Satya Nadella
Chief Executive Officer
Microsoft / Corporate Acquisitions
"""

req = urllib.request.Request(
    'http://localhost:8000/api/v1/emails/analyze',
    data=json.dumps({'raw_content': test_email}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)

try:
    with urllib.request.urlopen(req) as response:
        res = json.loads(response.read().decode('utf-8'))
        print('=== TEST EMAIL ANALYSIS RESULTS ===')
        print(f"Risk Score: {res.get('risk_score')} / 100")
        print(f"Verdict: {res.get('verdict') or res.get('severity')}")
        print(f"Probable Origin IP: {res.get('probable_origin_ip')}")
        print(f"Origin Location: {res.get('approximate_location')}")
        print(f"Lookalike Detected: {res.get('lookalike_detected') or res.get('is_lookalike')}")
        print(f"Evidence Fingerprint SHA-256: {res.get('sha256')}")
        print("\nAll Signals & Risk Deductions:")
        for r in res.get('risk_breakdown', []):
            print(f"  - {r}")
        for f in res.get('risk_factors', []):
            print(f"  * {f}")
except Exception as e:
    print(f"Error: {e}")
