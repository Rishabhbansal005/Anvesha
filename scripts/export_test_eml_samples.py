import os

target_dir = r"C:\Users\Ongkar\Desktop\Anvesh Report"
os.makedirs(target_dir, exist_ok=True)

eml_1 = """From: Billing Services <accounts-payable@invoicing-secure-portal.com>
To: target-employee@enterprise.local
Subject: Past Due: Outstanding Commercial Invoice #INV-992011 - Immediate Action Required
Date: Wed, 09 Sep 2026 09:15:00 +0000
Message-ID: <invoice-992011@invoicing-secure-portal.com>
Received: from mail.invoicing-secure-portal.com (198.51.100.45 [198.51.100.45])
    by mx.enterprise.local with ESMTP id 8812A
    for <target-employee@enterprise.local>; Wed, 09 Sep 2026 09:15:01 +0000
Authentication-Results: mx.enterprise.local;
    spf=fail (sender IP 198.51.100.45 is not permitted by domain invoicing-secure-portal.com);
    dkim=fail header.i=@invoicing-secure-portal.com;
    dmarc=fail (p=none)
Content-Type: multipart/mixed; boundary="----=_Part_99124_1082"
MIME-Version: 1.0

------=_Part_99124_1082
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

Dear Accounts Department,

Please find attached the final billing statement for Invoice #INV-992011. 
Our records indicate this balance is currently 45 days overdue.

To avoid service suspension and contractual penalties, review the attached invoice breakdown immediately and remit balance via wire transfer today.

Attachment: Invoice_Statement_992011.pdf.iso
SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Regards,
Automated Corporate Billing Team
------=_Part_99124_1082--
"""

eml_2 = """From: Global IT Support Desk <helpdesk-notice@service-corp-update.com>
Reply-To: security-dispatcher@collector-redirect.net
To: all-staff@enterprise.local
Subject: Critical System Alert: Mandatory Security Patch Deployment for All Workstations
Date: Wed, 09 Sep 2026 09:20:00 +0000
Message-ID: <patch-alert-7721@service-corp-update.com>
Received: from relay02.external-mail-route.com (203.0.113.88 [203.0.113.88])
    by mx.enterprise.local with ESMTP id 9918B
    for <all-staff@enterprise.local>; Wed, 09 Sep 2026 09:20:02 +0000
Authentication-Results: mx.enterprise.local;
    spf=softfail (sender IP 203.0.113.88);
    dkim=neutral;
    dmarc=fail

Dear Staff Member,

An urgent zero-day security advisory has been issued across the corporate network. 
All workstations are required to execute the mandatory compliance diagnostic tool immediately to retain intranet and email access.

Click the diagnostic gateway below to verify your workstation configuration:
hxxps://internal-patch-diagnostic.collector-redirect[.]net/verify?uid=staff991

Failure to run this check within 2 hours will result in automatic directory account suspension.

IT Systems Administration & Global Operations
"""

eml_3 = """From: Network Decryption Desk <support@recovery-key-portal.org>
To: executive-leadership@enterprise.local
Subject: Attention: Network Data Encryption Notice - Recovery Instructions Inside
Date: Wed, 09 Sep 2026 09:25:00 +0000
Message-ID: <lock-notice-404@recovery-key-portal.org>
Received: from exit-node.tor-transit-route.net (185.220.101.5 [185.220.101.5])
    by mx.enterprise.local with ESMTP id 1045C
    for <executive-leadership@enterprise.local>; Wed, 09 Sep 2026 09:25:02 +0000
Authentication-Results: mx.enterprise.local;
    spf=fail;
    dkim=fail;
    dmarc=fail

YOUR NETWORK STORAGE HAS BEEN ENCRYPTED WITH MILITARY-GRADE AES-256 CIPHER.

All proprietary databases, email archives, financial ledgers, and virtual machine disks have been locked. 
Attempting to decrypt these files using third-party tools will result in permanent key corruption and permanent data loss.

To purchase the private master key and prevent publication of confidential records on the public leak mirror, follow these instructions:

1. Appoint a single negotiation representative.
2. Access the recovery portal: hxxp://recovery-key-portal[.]org/ticket?id=CORP-LOCK-881
3. Remit the initial security deposit within 72 hours.

Timer Countdown: 72:00:00 remaining.
After the deadline expires, the private decryption key will be automatically destroyed.
"""

files = {
    "test_sample_1_suspicious_attachment.eml": eml_1,
    "test_sample_2_worm_propagation_lure.eml": eml_2,
    "test_sample_3_ransomware_demand.eml": eml_3,
}

for fname, content in files.items():
    fpath = os.path.join(target_dir, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Written: {fpath}")

# Also copy into workspace docs for reference
workspace_samples_dir = r"C:\Users\Ongkar\Desktop\Avnesh\Anvesha-main\Anvesha-main\docs\test_samples"
os.makedirs(workspace_samples_dir, exist_ok=True)
for fname, content in files.items():
    fpath = os.path.join(workspace_samples_dir, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Backup in workspace: {fpath}")
