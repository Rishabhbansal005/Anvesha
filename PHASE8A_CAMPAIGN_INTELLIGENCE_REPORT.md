# ANVESH Phase 8A — Campaign Intelligence Foundation Report

**AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**  
**Module**: Campaign Intelligence & Deterministic Correlation Foundation  
**Status**: COMPLETED & FULLY VERIFIED  
**Date**: September 6, 2026  

---

## 1. Objective
The goal of Phase 8A is to establish the foundation for **Campaign Intelligence** within ANVESH. This enables the platform to identify whether multiple independently analyzed emails and forensic investigation cases exhibit observable relationships indicative of a shared threat campaign.

### Core Non-Attribution Principle
Campaign correlation is **not** attacker attribution. The system strictly operates on observable evidentiary data. In accordance with ANVESH forensic safety rules:
- The system **never** asserts: *"same attacker"*, *"attacker identified"*, *"this person sent all emails"*, or *"attacker location"*.
- The system **always** uses objective evidentiary nomenclature: *"Potential Campaign"*, *"Related Activity"*, *"Infrastructure Overlap"*, *"Campaign Confidence"*, *"Observed Relationship"*, and *"Correlation Evidence"*.

---

## 2. Existing Architecture Reused
Phase 8A cleanly builds upon existing ANVESH forensic components without duplicating data structures or altering frozen models:
- **Ingestion & Parsing (`app/api/v1/endpoints/emails.py`)**: RFC-822 header extraction, cryptographic authentication verification (SPF, DKIM, DMARC), transit relay hop traversal, and observable extraction (`IP`, `DOMAIN`, `URL`).
- **Database Layer (`app/database/supabase_client.py`)**: Supabase PostgREST gateway with local cache storage fallback, supporting resilient offline development and instant query resolution.
- **Observable Ledger (`iocs` & `cases`)**: Reuses the immutable case ledger and IOC table. Correlation queries match against existing observables without duplicating records.
- **Intelligence & Attribution Services (`app/services/intelligence_service.py`, `attribution_service.py`)**: Reuses authoritative BGP/ASN enrichment, RDAP registration records, and forensic attribution boundaries.
- **Model 3B Lookalike Service (`app/services/lookalike_service.py`)**: Reuses frozen Model 3B predictions (`trusted_domain`, `target_brand`, `signal`) as correlation evidence.

---

## 3. Campaign Data Model
A unified Campaign abstraction is implemented in `app/services/campaign_service.py` and backed by the database layer:

```text
Campaign
--------------------------------------------------------------------------------
campaign_id         TEXT UNIQUE (e.g., "ANV-26-CMP-D25D20")
name                TEXT (e.g., "Potential Campaign: Urgent Payment Update")
status              TEXT ("NEW", "ACTIVE", "REVIEW", "CLOSED")
confidence          TEXT ("HIGH", "MEDIUM", "LOW")
confidence_score    INTEGER (0 to 100)
case_count          INTEGER
email_count         INTEGER
ioc_count           INTEGER
first_observed_at   TIMESTAMPTZ (ISO UTC)
last_observed_at    TIMESTAMPTZ (ISO UTC)
explanation         TEXT (Deterministic machine-generated explanation)
evidence_summary    JSONB (Counts of shared Reply-To, domains, IPs, brand targets)
created_at          TIMESTAMPTZ
updated_at          TIMESTAMPTZ
```

### Confidence Scale
Campaign confidence reflects cumulative evidentiary weight, **never** probability of attacker identity:
- **`HIGH`** ($\ge 75$): Strong multi-signal overlap (e.g., matching non-freemail Reply-To address + matching suspicious observable domain).
- **`MEDIUM`** ($50 - 74$): Substantial observable overlap (e.g., matching Reply-To or non-cloud public IP combined with lexical subject pattern similarity).
- **`LOW`** ($< 50$): Weak or insufficient observable overlap; cases remain ungrouped (`campaign_id = null`).

---

## 4. Normalization Strategy
All evidence signals are normalized through deterministic, RFC-compliant transformation functions that safely compute comparison keys while **preserving original values**:

| Entity | Normalization Function | Transformation Rules | Original Preserved |
| :--- | :--- | :--- | :--- |
| **Email Address** | `normalize_email` | Extracts address from RFC-822 display format (`Name <addr>`); lowercases domain portion; preserves local part. | Yes (`original`) |
| **Domain** | `normalize_domain` | Lowercases string; strips trailing dots; decodes IDNA/punycode (`xn--...`). | Yes (`original`) |
| **URL** | `normalize_url` | Lowercases scheme and hostname; extracts root host domain independently; normalizes path. | Yes (`original`) |
| **IP Address** | `normalize_ip` | Parses through Python `ipaddress.ip_address` into canonical IPv4/IPv6 representation; identifies private/loopback/cloud ranges. | Yes (`original`) |
| **Subject** | `normalize_subject` | Iteratively strips reply/forward prefixes (`RE:`, `FW:`, `FWD:`, `AW:`, `SV:`, `[EXTERNAL]`, `URGENT:`); collapses whitespace; lowercases. | Yes (`original`) |

---

## 5. Correlation Signals & 6. Correlation Weights
The deterministic correlation engine calculates explainable weights without LLMs or opaque black-box clustering:

| Category | Signal Identifier | Weight | Strength | Evidentiary Description |
| :--- | :--- | :--- | :--- | :--- |
| **Infrastructure** | `EXACT_SUSPICIOUS_DOMAIN` | **+35** | STRONG | Matching non-freemail domain observable present in both cases. |
| **Identity** | `EXACT_REPLY_TO` | **+35** | STRONG | Identical Reply-To address specified across distinct messages. |
| **Threat IOC** | `EXACT_IOC_OVERLAP` | **+30** | STRONG | Identical malicious/suspicious payload URL or observable indicator. |
| **Infrastructure** | `EXACT_PUBLIC_IP` | **+25** | STRONG | Matching originating public network transit IP (non-cloud, non-resolver). |
| **Lookalike** | `SAME_LOOKALIKE_TARGET` | **+25** | STRONG | Model 3B detects identical enterprise brand impersonation target. |
| **Identity** | `EXACT_SENDER` | **+20** | MEDIUM | Identical normalized sender address observed across cases. |
| **Identity** | `REPLY_TO_DOMAIN_OVERLAP` | **+20** | MEDIUM | Distinct local mailboxes sharing custom Reply-To domain. |
| **Identity** | `SENDER_DOMAIN_OVERLAP` | **+15** | MEDIUM | Distinct local mailboxes sharing custom sender domain. |
| **Infrastructure** | `EXACT_MSG_ID_DOMAIN` | **+15** | MEDIUM | Shared originating mail server Message-ID domain infrastructure. |
| **Content** | `EXACT_NORMALIZED_SUBJECT` | **+15** | MEDIUM | Identical normalized subject pattern after prefix stripping. |
| **Content** | `SUBJECT_LEXICAL_SIMILARITY`| **+12** | MEDIUM | High token Jaccard similarity ($\ge 75\%$) between subject lines. |
| **Content** | `COMMON_FINANCIAL_PHRASE` | **+10** | WEAK-MED | Shared financial coercion/BEC phrasing (e.g. "urgent payment"). |
| **Temporal** | `TEMPORAL_PROXIMITY_CLOSE` | **+10** | SUPPORT | Events observed within $\le 7$ days of each other. |
| **Temporal** | `TEMPORAL_PROXIMITY_MODERATE`| **+5** | SUPPORT | Events observed within $8 - 14$ days of each other. |
| **Context** | `SHARED_ASN_CONTEXT` | **+2** | WEAK | Shared Autonomous System Number (ASN). Context only; cannot correlate alone. |

Every correlation evaluation returns an explainable JSON payload detailing exact signals:
```json
{
  "related": true,
  "confidence": "HIGH",
  "score": 85,
  "reasons": [
    {
      "signal": "EXACT_REPLY_TO",
      "strength": "STRONG",
      "weight": 35,
      "description": "Both cases direct replies to the identical address: 'threat-drop@phantom-operations.net'."
    },
    {
      "signal": "EXACT_SUSPICIOUS_DOMAIN",
      "strength": "STRONG",
      "weight": 35,
      "description": "Observed overlap on suspicious domain observable: 'phantom-operations.net'."
    },
    {
      "signal": "EXACT_NORMALIZED_SUBJECT",
      "strength": "MEDIUM",
      "weight": 15,
      "description": "Identical normalized subject line pattern: 'urgent financial mandate'."
    }
  ]
}
```

---

## 7. False-Positive Protections
To prevent spurious clustering, strict guards suppress weak environmental signals:
1. **Public Freemail Guard**: `gmail.com`, `yahoo.com`, `outlook.com`, `hotmail.com`, `protonmail.com`, `icloud.com`, etc. are explicitly barred from triggering domain overlap signals.
2. **Cloud Gateway Guard**: `MICROSOFT_365_OR_AZURE`, `GOOGLE_WORKSPACE_OR_GCP`, `AMAZON_WEB_SERVICES`, and `CLOUDFLARE` IPs receive a `SHARED_PUBLIC_GATEWAY_GUARD` (weight +0) to prevent associating independent emails simply because both transit Microsoft 365 or Google.
3. **Public Resolver Guard**: `8.8.8.8`, `1.1.1.1`, `9.9.9.9`, etc. are ignored for origin IP correlation.
4. **ASN Guard**: Shared ASN provides only +2 points of environmental context and can never exceed the 50-point correlation threshold on its own.

---

## 8. Campaign Creation & Ingestion Logic
During email ingestion (`/api/v1/emails/analyze`):
1. Email is parsed, hops reconstructed, observables extracted, and risk assessed.
2. Case and email records are registered in Supabase.
3. The deterministic correlation engine evaluates the incoming case against candidate investigations.
4. **If score $\ge 50$**:
   - If the candidate case already belongs to a campaign, the current case is attached to it.
   - If the candidate case is unassigned, a **NEW** Potential Campaign is created (e.g. `ANV-26-CMP-XXXX`), and both cases are linked to it.
   - Campaign counts (`case_count`, `email_count`, `ioc_count`), timeline milestones, and deterministic explanations are recalculated and persisted.
5. **If score $< 50$**:
   - The case remains standalone (`campaign_id = null`).
   - Emails are **never** forced into arbitrary campaigns.

---

## 9. Campaign Explanation
Every campaign includes a deterministic, machine-generated explanation:
> *"2 analyzed cases (2 emails) are grouped as related activity based on 1 matching Reply-To address(es), 1 shared suspicious domain(s), targeted impersonation of 'binance.com' observed within a 1-day period. The available evidence indicates related threat infrastructure and behavior. Actor identity is not established; this grouping represents observable infrastructure correlation."*

---

## 10. API Endpoints
All endpoints follow existing REST conventions and zero-fabrication guidelines:

| Endpoint | Method | Purpose | Response Highlights |
| :--- | :---: | :--- | :--- |
| `/api/v1/campaigns` | `GET` | List active campaigns with filters (`status`, `confidence`, `q`) | `items`, `total`, `is_simulated_data: false` |
| `/api/v1/campaigns/{id}` | `GET` | Detailed campaign dossier | Metadata, linked cases, explanation, observables summary, timeline |
| `/api/v1/campaigns/{id}/relationships` | `GET` | Graph relationship foundation | Nodes (`CAMPAIGN`, `CASE`, `EMAIL`, `DOMAIN`, `IP`, `URL`, `REPLY_TO`), Edges (`INCLUDES_CASE`, `INGESTED_EMAIL`, `OBSERVED_DOMAIN`, etc.) |
| `/api/v1/campaigns/{id}/timeline` | `GET` | Chronological event timeline | Real timestamped events (`CASE_REGISTERED`, `IP_OBSERVED`, `REPLY_TO_OBSERVED`) |
| `/api/v1/campaigns/correlate` | `POST` | On-demand correlation analysis | Evaluates two cases without modifying state; returns score, confidence, and itemized reasons |

---

## 11. Timeline & Graph Foundations (Phases 8B/8C Ready)
- **Timeline**: Built exclusively from stored database timestamps. Events are dynamically reconstructed and sorted chronologically. Zero synthetic dates are ever created.
- **Graph Foundation**: Complete node-edge adjacency structure provided via `/api/v1/campaigns/{id}/relationships`. This serves as the direct backend foundation for future interactive visual graph exploration.

---

## 12. Attribution Boundary Invariants
The Campaign Intelligence layer strictly enforces forensic non-attribution:
- `Origin Confidence` remains strictly derived from Received header transit analysis.
- `Actor Identity` remains strictly `NOT ESTABLISHED`.
- IP geolocation remains designated as *infrastructure location*, not physical actor location.
- SPF/DKIM/DMARC cryptographic verdicts remain unaltered.

---

## 13. UI Implementation
### Web Workstation (`web/src/pages/InvestigationWorkspace.tsx`)
- **Potential Campaign Panel**: When a case belongs to a campaign, displays `Potential Campaign: ANV-26-CMP-XXXX`, Confidence badge (`HIGH`/`MEDIUM`), related cases/IOC count, itemized reasons list (*"Why Related"*), and the deterministic explanation.
- **Campaign Dossier Modal**: Modal triggered by "View Campaign" displaying full cluster details, linked investigations, and chronological evidence timeline.
- **Design Philosophy**: Adheres to the established Apple-inspired, high-contrast dark forensic design system.

### Mobile App (`mobile/src/screens/CasesScreen.tsx`)
- **Operational Indicator**: Case cards display a compact `POTENTIAL CAMPAIGN` tag with confidence rating (`HIGH CONFIDENCE`), campaign ID, and key indicators (`• Observed Infrastructure Overlap`, `• Shared Threat Indicators`).

---

## 14. Test Results & Verification
A comprehensive test suite with 17 dedicated tests was implemented in `backend/tests/test_campaign_intelligence.py`. The complete test suite (49 total tests) passed with 100% success rate:

```text
tests/test_campaign_intelligence.py::test_exact_domain_overlap_correlates PASSED
tests/test_campaign_intelligence.py::test_exact_reply_to_overlap_correlates PASSED
tests/test_campaign_intelligence.py::test_same_suspicious_ioc_correlates PASSED
tests/test_campaign_intelligence.py::test_highly_similar_subjects_contribution PASSED
tests/test_campaign_intelligence.py::test_same_gmail_infrastructure_only_not_related PASSED
tests/test_campaign_intelligence.py::test_same_microsoft_365_infrastructure_only_not_related PASSED
tests/test_campaign_intelligence.py::test_same_asn_only_is_weak_and_not_strong_enough PASSED
tests/test_campaign_intelligence.py::test_different_unrelated_emails_not_related PASSED
tests/test_campaign_intelligence.py::test_confidence_scale_tiers PASSED
tests/test_campaign_intelligence.py::test_correlation_explanation_preserves_non_attribution PASSED
tests/test_campaign_intelligence.py::test_campaign_creation_and_attachment_lifecycle PASSED
tests/test_campaign_intelligence.py::test_timeline_chronological_ordering PASSED
tests/test_campaign_intelligence.py::test_original_evidence_remains_unchanged PASSED
tests/test_campaign_intelligence.py::test_attribution_boundary_remains_unaltered PASSED
tests/test_campaign_intelligence.py::test_model_1_phishing_hash_unchanged PASSED
tests/test_campaign_intelligence.py::test_model_2_bec_hash_unchanged PASSED
tests/test_campaign_intelligence.py::test_model_3b_lookalike_hash_unchanged PASSED

================= 49 passed, 35 warnings in 63.82s =================
```

### Build & Typecheck Verifications
- **Web Frontend**: `npm run build` in `web/` passed in 5.64s (0 errors).
- **Mobile App**: `npx tsc --noEmit` in `mobile/` passed with exit code 0 (0 errors).

---

## 15. Model Integrity Verification
All frozen ML model weights were cryptographically verified using SHA-256 and remain 100% untouched:

| Model | Path | Expected SHA-256 | Actual SHA-256 | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Model 1 (Phishing)** | `ml/models/phishing_baseline_v1/model.joblib` | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | **FROZEN & VERIFIED** |
| **Model 2 (BEC)** | `ml/models/bec_baseline_v1/model.joblib` | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` | **FROZEN & VERIFIED** |
| **Model 3B (Lookalike)**| `ml/models/lookalike_domain_v1/model.joblib` | `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559` | `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559` | **FROZEN & VERIFIED** |

---

## 16. Known Limitations
1. **Campaign correlation does not prove common authorship**: Multiple threat actors may independently purchase similar bulletproof hosting, reuse open-source phishing kits, or target the same brand.
2. **Shared cloud infrastructure creates weak relationships**: Organizations utilizing hyperscale email relays (e.g. Microsoft 365, Google Workspace) share originating network infrastructure. Correlation algorithms explicitly suppress these shared gateways.
3. **Compromised legitimate accounts produce authentic cryptographic signatures**: BEC attacks originating from hijacked executive accounts may display valid SPF/DKIM/DMARC pass verdicts. Correlation must rely on Reply-To divergence and content indicators.
4. **Correlation quality depends on observable evidence**: Emails with missing headers or stripped Received transit sequences cannot be reliably correlated.
5. **Content similarity alone is insufficient for attribution**: Phishing templates are widely shared and plagiarized across independent threat groups.

---

## 17. Next Recommended Phase: Phase 8B
With the deterministic foundation complete, the recommended next steps are:
1. **Interactive Campaign Graph Visualization (Phase 8B)**: Render the node-edge relationship structure using Cytoscape.js or React Flow within the Investigation Workspace.
2. **Cross-Case Pivot Navigation**: Enable analysts to click on any observable node (e.g., an IP or domain) and pivot directly to all linked investigations.
3. **Timeline Event Scrubbing**: Add visual playback of campaign timeline milestones across days and weeks.
