# ANVESH — Model 3A Dataset Audit & Ground-Truth Governance Document

**Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Model:** Model 3A (Identity & Header Impersonation Detection)  
**Phase:** Phase 9A (Dataset Investigation, Governance Decision, and Deterministic Baseline)  
**Governance Invariant:** Model 1, Model 2, and Model 3B REMAIN COMPLETELY FROZEN & UNTOUCHED  
**Decision:** **MODEL TRAINING BLOCKED — GOVERNED DETERMINISTIC BASELINE DEPLOYED**

---

## 1. Executive Summary & Governance Decision

> [!IMPORTANT]
> ### Formally Documented Dataset Governance Decision
> **Model 3A is implemented as a governed deterministic baseline because no sufficiently verified public identity-impersonation ground-truth corpus was established.**
> 
> ANVESH strictly enforces a zero-fabrication policy across all machine learning and forensic pipelines. Fabricating synthetic display-name pairings and labeling them as real-world ground truth violates forensic integrity and yields overfitted, uncalibrated models that fail on real-world adversaries. Implementing a deterministic, explainable rule engine based on established RFC-822 header security semantics is scientifically superior and fully transparent.

---

## 2. Investigation of Candidate Datasets

We investigated candidate public email and threat corpora to determine whether any established dataset could provide legitimate, verified ground truth for executive display-name impersonation, Reply-To spoofing, and sender identity mismatches.

### Candidate 1: Enron Email Corpus (CALO / CMU)
- **Source / URL:** Carnegie Mellon University (`cs.cmu.edu/~enron/`)
- **Size:** ~517,431 messages across 150 users
- **License:** Public Domain / Research
- **Provenance:** Subpoena disclosure from FERC investigation of Enron Corp.
- **Real vs. Synthetic:** 100% Real enterprise email communications.
- **Headers Preserved:** Full RFC-822 headers preserved in original MIME files.
- **Identity Labels:** **NONE**. All communications are benign internal/external operational correspondence. There are no labeled spoofing attacks, no adversary ground truth, and no annotated executive impersonation pairs.
- **Evaluation:** Unsuitable for training impersonation classifiers; provides only benign baseline noise.

### Candidate 2: Jose Nazario Phishing Corpus
- **Source / URL:** Monkey.org (`monkey.org/~jose/phishing/`)
- **Size:** ~4,500 phishing emails (spanning 2005–2015)
- **License:** Open Academic
- **Provenance:** Curated honeypot and user-submitted phishing reports.
- **Real vs. Synthetic:** Real historical phishing attacks.
- **Headers Preserved:** RFC-822 headers preserved with varying degrees of sanitization/redaction.
- **Identity Labels:** **BINARY ONLY (Phishing vs. Ham)**. Does not annotate whether the phishing relied on display-name spoofing, credential lure, attachment malware, or link deception. Does not include a verified enterprise identity directory to establish who was being impersonated.
- **Evaluation:** Lacks fine-grained identity relationship annotations.

### Candidate 3: IWSPA AP (Anti-Phishing Shared Task 2018)
- **Source / URL:** International Workshop on Social Web for Disaster Management / IWSPA 2018
- **Size:** ~5,000 sanitized emails
- **License:** Academic Research Agreement
- **Provenance:** Sanitized blend of public phishing reports and legitimate collections.
- **Real vs. Synthetic:** Partially anonymized real emails.
- **Headers Preserved:** Partial / redacted. Many sender and header fields are masked or altered for privacy.
- **Identity Labels:** Binary phishing label only. No ground truth regarding executive authority, vendor relationships, or display-name to domain mappings.
- **Evaluation:** Redaction destroys subtle header discrepancies required for identity impersonation analysis.

### Candidate 4: SpamAssassin Public Corpus
- **Source / URL:** Apache SpamAssassin (`spamassassin.apache.org/old/publiccorpus/`)
- **Size:** ~6,000 messages
- **License:** Apache 2.0
- **Provenance:** Early 2000s spam/ham donations.
- **Real vs. Synthetic:** Real spam and mailing-list messages.
- **Headers Preserved:** Preserved.
- **Identity Labels:** Binary spam/ham. No BEC, no targeted CEO fraud, and no executive display name annotations.
- **Evaluation:** Completely obsolete for modern targeted identity impersonation.

### Candidate 5: Zenodo BEC and Phishing Datasets
- **Source / URL:** Zenodo Open Repository (e.g., DOI: 10.5281/zenodo.7108924 and related)
- **Size:** 1,000–10,000 text records
- **License:** CC BY 4.0
- **Provenance:** Curated collections of social engineering text.
- **Real vs. Synthetic:** Predominantly stripped body text or synthetic prompts.
- **Headers Preserved:** **NO HEADERS**. Datasets strip RFC-822 headers and retain only body text.
- **Identity Labels:** Keyword/topic annotations only.
- **Evaluation:** Cannot be used for header or identity impersonation because RFC-822 transport telemetry is absent.

---

## 3. Dataset Audit Scorecard

| Candidate Corpus | Preserves RFC-822 Headers | Ground-Truth Identity Mappings | Labeled Impersonation Types | Real-World Provenance | Leakage-Free Partitioning | Training Justified? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Enron Email Corpus** | YES | NO (Benign only) | NO | YES | N/A | **NO (Ham only)** |
| **Nazario Phishing** | YES (Partial) | NO | NO (Binary phish) | YES | NO | **NO (No identity labels)** |
| **IWSPA AP 2018** | NO (Redacted) | NO | NO | PARTIAL | NO | **NO (Redacted headers)** |
| **SpamAssassin** | YES | NO | NO | YES | N/A | **NO (Outdated spam)** |
| **Zenodo BEC Collections** | NO (Body only) | NO | NO | PARTIAL | NO | **NO (No headers)** |

---

## 4. Governance Decision & Architecture Justification

Because no candidate corpus provides verified, labeled identity impersonation relationships with preserved RFC-822 headers:
1. **Machine learning model training is strictly BLOCKED for Model 3A.**
2. **Model 3A is implemented as a Governed Deterministic Baseline Engine.**
3. The deterministic baseline computes an explainable `identity_impersonation_score` (0–100) based on clear structural and lexical header relationships:
   - Display name vs. trusted identity mapping mismatch
   - Reply-To address vs. From address disparity
   - Executive display name paired with public freemail/external domains
   - Inconsistencies between sender local-part/domain and display name
   - Support from Model 3B (lookalike domain evidence)
   - Cryptographic authentication context (SPF, DKIM, DMARC)
4. The score is **never** presented as an uncalibrated probability.
5. Attribution boundaries are strictly preserved: **Actor Identity: NOT ESTABLISHED**.

---

## 5. Future Requirements for Real-World Model 3A Training

To justify training a future statistical machine learning model for Model 3A, a prospective dataset must meet all of the following requirements:
- **Preserved RFC-822 / MIME Headers:** Intact `From`, `To`, `Reply-To`, `Return-Path`, `Authentication-Results`, `Received`, and `Message-ID`.
- **Verified Ground-Truth Identity Registry:** Explicit enterprise organizational charts mapping names, titles, corporate domains, and verified external vendor emails.
- **Explicit Impersonation Sub-Type Labels:** Display-name spoofing, cousin-domain spoofing, Reply-To hijacking, and compromised account BEC.
- **Dual-Party Cryptographic Verification:** Clear audit logs confirming whether sender mailboxes were authentic or spoofed at delivery time.
- **Strict Entity-Level Partitioning:** Zero overlap of target identities between train, validation, and test splits.
