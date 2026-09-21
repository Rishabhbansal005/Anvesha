import requests

test_email = """Received: from mail-relay.evasion-drop.net (mail-relay.evasion-drop.net [185.220.101.5])
    by mx.corporate-target.com with ESMTP id 84HF928FJA
    for <cfo@target-corp.com>; Wed, 09 Sep 2026 01:45:00 +0530
From: "Satya Nadella (CEO Office)" <exec-alert@micr0soft.com>
To: "Chief Financial Officer" <cfo@target-corp.com>
Reply-To: "Shadow Operations" <wire-dept@external-shadow-account.ru>
Return-Path: <bounce@evasion-drop.net>
Subject: URGENT: Wire Transfer of $84,500 and Verify Suspended Account Immediately
Date: Wed, 09 Sep 2026 01:45:00 +0530
Message-ID: <92847291847.20260909@micr0soft.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

URGENT AND STRICTLY CONFIDENTIAL - EXECUTIVE WIRE TRANSFER REQUIRED

Dear Finance Team,

I am currently in an executive board meeting with investors and my phone is on silent. 
Please process an immediate wire transfer of $84,500.00 USD to our new vendor account before 5:00 PM today.
Failure to process this today will breach our contract.

Additionally, our corporate Microsoft 365 executive credentials have been flagged for suspension.
Please verify your identity and password immediately by clicking below:
https://login.micr0soft.com/auth/login.php?user=cfo@target-corp.com

Confirm once the funds have been dispatched.

Regards,
Satya Nadella
Chief Executive Officer
Microsoft Corporation
"""

try:
    res = requests.post(
        'http://localhost:8000/api/v1/emails/analyze',
        data={'raw_headers': test_email},
        timeout=60
    )
    print('Status Code:', res.status_code, flush=True)
    data = res.json()
    print('Risk Score:', data.get('risk_score'), '/ 100', flush=True)
    print('Risk Level:', data.get('risk_level'), flush=True)
    print('Probable Origin IP:', data.get('probable_origin_ip'), flush=True)
    print('Origin Location:', data.get('approximate_location'), flush=True)
    print('Sender:', data.get('sender'), flush=True)
    print('Subject:', data.get('subject'), flush=True)
    print('\nReasons Identified:', flush=True)
    for r in data.get('reasons', []):
        print('  *', r, flush=True)
except Exception as e:
    print('Error:', e, flush=True)
