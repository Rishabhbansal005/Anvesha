# ANVESH — Model 3A Baseline Evaluation & Methodology

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Model:** Model 3A (Identity & Header Impersonation Detection)  
**Version:** `model3a_deterministic_v1`  
**Phase:** Phase 9A  
**Architecture:** Governed Deterministic Evidence Engine  
**Attribution Boundary:** Actor Identity: NOT ESTABLISHED

---

## 1. Objective & Scope

Model 3A evaluates technical RFC-822 email headers and display-name metadata to answer:
> **"Does the observed email contain evidence that the sender identity may be impersonating another known/trusted identity?"**

It strictly does NOT answer:
- "Who sent this email?"
- "Who is the attacker?"
- "Where is the attacker?"

---

## 2. Evaluation Signals & Additive Weights

The engine computes an uncalibrated, explainable `identity_impersonation_score` ranging from **0 to 100**.

| Signal ID | Signal Name | Points | Condition & Rationale |
| :--- | :--- | :--- | :--- |
| **SIGNAL 1** | `DISPLAY_NAME_DOMAIN_MISMATCH` | **+30** | Observed display name matches a registered trusted identity (e.g. executive or key supplier), but observed sender domain differs from the trusted corporate domain. |
| **SIGNAL 2** | `EXECUTIVE_EXTERNAL_DOMAIN` | **+25** | Display name contains executive titles or matches leadership identity, but originates from public freemail or external consumer infrastructure. |
| **SIGNAL 3** | `SUSPICIOUS_SENDER_DOMAIN_RELATION` | **+15** | Personal display name paired with generic operational sender local-part (`billing`, `payments`, `wire`, `accounts`) on an external domain. |
| **SIGNAL 4** | `REPLY_TO_MISMATCH` | **+25** | The RFC-822 `Reply-To` address differs from the observed `From` sender address. Indicator of route manipulation or reply diversion. |
| **SIGNAL 5** | `DISPLAY_NAME_TRUSTED_DOMAIN_MISMATCH` | **+15** | Display name references trusted organization domain while sender domain is an unrelated third-party. |
| **SIGNAL 6** | `MODEL3B_LOOKALIKE_SUPPORT` | **+15** | Corroboration from Model 3B when the sender domain is identified as a lookalike/typosquat of the target brand. |
| **SIGNAL 7** | `AUTH_FAILURE_CONTEXT` | **+10** | Cryptographic authentication check (`SPF`, `DKIM`, or `DMARC`) failed (`FAIL`), increasing the probability of transport spoofing. |

**Score Normalization:**  
$$\text{identity\_impersonation\_score} = \min(100, \sum \text{Points})$$

**Detection Threshold:** $\ge 40$ points  
**Confidence Bands:**
- $\ge 70$: `HIGH`
- $40 - 69$: `MEDIUM`
- $1 - 39$: `LOW`
- $0$: `NONE`

---

## 3. Governance Guarantees & Invariants

1. **Authentication Invariant (Compromised Account Protection):**
   - Authentication PASS (`SPF: PASS`, `DKIM: PASS`, `DMARC: PASS`) does NOT reduce, reset, or suppress identity impersonation scores.
   - When authentication passes on an impersonated message, the system attaches:
     > *"Authentication passed (SPF/DKIM/DMARC PASS), but identity impersonation indicators remain. Possible mailbox compromise or external lookalike infrastructure."*
2. **Attribution Invariant:**
   - Identity signals represent technical and lexical discrepancies.
   - Actor identity is permanently registered as **`Actor Identity: NOT ESTABLISHED`**.
3. **Model 3B Non-Duplication:**
   - Model 3B evaluates domain lexical/structural similarity independently.
   - Model 3A imports Model 3B output solely as corroborating context (+15 points), without modifying Model 3B weights or re-running random forest models.

---

## 4. Evaluation Across Key Test Fixtures

| Test Scenario | Input Description | Expected Signals | Impersonation Score | Confidence | Attribution Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Fixture 1: Executive on Freemail** | "Anita Sharma — CFO" `<anita.sharma@gmail.com>` | Signal 1 (+30), Signal 2 (+25) | **55** | `MEDIUM` | NOT ESTABLISHED |
| **Fixture 2: Legitimate Internal Email** | "Anita Sharma" `<anita.sharma@company.com>` | None | **0** | `NONE` | NOT ESTABLISHED |
| **Fixture 3: Reply-To Divergence** | From: `ceo@company.com`, Reply-To: `divert@external.com` | Signal 4 (+25) | **25** | `LOW` | NOT ESTABLISHED |
| **Fixture 4: Lookalike + Executive Name** | "John Smith" `<john@m1crosoft-security.com>`, Model 3B: HIGH | Signal 1 (+30), Signal 6 (+15) | **45** | `MEDIUM` | NOT ESTABLISHED |
| **Fixture 5: Full Deception BEC Vector** | "Anita Sharma — CFO" `<anita@evil.com>`, Reply-To: `<wire@hacker.com>`, SPF FAIL | Signal 1 (+30), Signal 2 (+25), Signal 4 (+25), Signal 7 (+10) | **90** | `HIGH` | NOT ESTABLISHED |
| **Fixture 6: Compromised Mailbox** | Legitimate internal account compromised, SPF/DKIM PASS | No spoofed sender headers; behavior BEC risk handled by Risk Engine | **0 (or contextual)** | Safe Baseline | NOT ESTABLISHED |
