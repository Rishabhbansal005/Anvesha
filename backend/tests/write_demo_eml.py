import os

email_content = """From: "PayPal Security and Billing Team" <security-alert@paypa1.com>
To: victim.analyst@targetcorp.com
Subject: [URGENT] Your PayPal Account Has Been Suspended - Immediate Wire Transfer and Verification Required
Date: Mon, 21 Sep 2026 09:15:00 +0000
Message-ID: <20260921091500.SECURITY.ALERT.09871@paypa1.com>
Reply-To: paypal.security.urgent@gmail.com
Return-Path: <bounces@paypa1.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
X-Mailer: SecurityAlertMailer v4.2
X-Originating-IP: [185.220.101.45]
Authentication-Results: mx.targetcorp.com;
    spf=fail (domain paypa1.com does not designate 185.220.101.45 as permitted sender)
        smtp.mailfrom=security-alert@paypa1.com;
    dkim=fail (signature verification failed)
        header.i=@paypa1.com header.s=default header.b=Xk3mNpQr;
    dmarc=fail (p=reject sp=reject dis=quarantine)
        header.from=paypa1.com
Received-SPF: fail (mx.targetcorp.com: domain of security-alert@paypa1.com does not designate 185.220.101.45 as permitted sender) receiver=mx.targetcorp.com; client-ip=185.220.101.45; envelope-from=security-alert@paypa1.com;
Received: from internal-relay.targetcorp.com (10.0.1.5) by mail.targetcorp.com (10.0.1.10) with SMTP id e2f3a4b; Mon, 21 Sep 2026 09:15:22 +0000
Received: from edge-firewall.targetcorp.com (198.51.100.25) by internal-relay.targetcorp.com (10.0.1.5) with ESMTP id d1c2b3a; Mon, 21 Sep 2026 09:15:15 +0000
Received: from mail.paypa1.com (mail.paypa1.com [185.220.101.45]) by edge-firewall.targetcorp.com (198.51.100.25) with ESMTPS id c0b1a2f (TLSv1.3) for <victim.analyst@targetcorp.com>; Mon, 21 Sep 2026 09:15:02 +0000

Dear Valued PayPal Customer,

We detected unauthorized logins to your PayPal corporate business account from an unknown device located in Moscow, Russia (IP: 185.220.101.45) on September 21, 2026.

Your account access has been temporarily restricted to prevent fraudulent transactions.

CRITICAL ACTION REQUIRED WITHIN 24 HOURS:
To restore your full merchant capabilities and avoid permanent closure of your balance:
1. Complete identity reverification immediately by visiting our secure portal:
   http://paypa1-security-update.com/verify-identity?token=9f83ac4e21b7

2. If any unauthorized invoice overdue is pending, an emergency wire transfer to our escrow account is required to safeguard pending merchant settlement funds:
   - Account Name: PayPal Corporate Escrow Clearing
   - Bank: Metropolitan Escrow International
   - Account Number: 8839-2019-4482
   - Routing: 021000021
   - SWIFT: MEINUS33

Failure to verify within 24 hours will result in permanent asset liquidation under Section 10.2 of PayPal Merchant User Agreement.

Do not reply directly to this automated notification. If you have urgent questions, reply to our direct security desk at: paypal.security.urgent@gmail.com.

Sincerely,
PayPal Corporate Fraud Prevention and Anti-Money Laundering Group
Transaction Security ID: PP-SEC-2026-98112
"""

dest = os.path.expanduser(r"~\Desktop\ANVESH_ULTIMATE_DEMO.eml")
with open(dest, "wb") as f:
    f.write(email_content.encode("utf-8"))

print(f"Wrote {len(email_content)} characters to {dest}")
with open(dest, "rb") as f:
    header = f.read(15)
print("Header bytes:", header)
assert not header.startswith(b"\xef\xbb\xbf"), "Error: File has BOM!"
print("SUCCESS: Valid UTF-8 file created without BOM.")
