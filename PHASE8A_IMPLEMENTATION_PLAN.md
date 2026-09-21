# ANVESH Phase 8A — Campaign Intelligence Foundation Implementation Plan

## 1. Existing Relevant Architecture
- **Ingestion Pipeline (`app/api/v1/endpoints/emails.py`)**:
  - Ingests RFC-822 messages (`.eml` or raw text).
  - Parses headers: `From`, `To`, `Subject`, `Reply-To`, `Return-Path`, `Message-ID`.
  - Analyzes transit hops and isolates `probable_origin_ip` and `origin_confidence`.
  - Extracts observables (`IP`, `DOMAIN`, `URL`).
  - Evaluates Model 1 (Phishing), Model 2 (BEC via risk engine heuristics), and Model 3B (Lookalike Domain).
  - Calculates composite risk score and generates attribution boundaries.
  - Persists records to Supabase tables: `cases`, `emails`, `evidence`, `iocs`, `infrastructure_intelligence`, `attribution_assessments`, `evidence_gaps`, `alerts`.
- **Database Layer (`app/database/supabase_client.py`)**:
  - Centralized Supabase client with PostgREST gateway.
  - In-memory `_local_cache` providing offline and fallback storage for all entities (`cases`, `emails`, `evidence`, `iocs`, `campaigns`, etc.).
- **Investigation Workspace (`web/src/pages/InvestigationWorkspace.tsx`)**:
  - SOC analyst workstation displaying cases, headers, hops, observables, infrastructure intelligence, attribution boundaries, and evidence gaps.
- **Mobile Companion (`mobile/src/screens/CasesScreen.tsx`, `QuickLookupScreen.tsx`)**:
  - Tactical interface displaying real-time case ledger, attribution boundaries, and recommended next actions.

---

## 2. Existing Reusable Entities
- `cases`: `id`, `case_number`, `title`, `description`, `risk_score`, `risk_level`, `threat_type`, `probable_origin_ip`, `origin_confidence`, `campaign_id`, `created_at`.
- `emails`: `id`, `case_id`, `message_id`, `subject`, `sender`, `reply_to`, `return_path`, `recipient`, `body_hash_sha256`, `delivery_hops_json`.
- `iocs`: `id`, `case_id`, `ioc_type` (`IP`, `DOMAIN`, `URL`), `value`, `reputation_score`.
- `infrastructure_intelligence`: `case_id`, `ip_address`, `asn`, `isp`, `organization`, `hosting_provider`, `cloud_classification`.
- `campaigns` (Existing base table in schema): `id`, `name`, `threat_type`, `description`, `confidence_score`, `created_at`.

---

## 3. New Entities & Data Models Required
### A. Campaign Schema
- `campaign_id`: Human-readable identifier (e.g., `ANV-26-CMP-A8F2`).
- `name`: Descriptive campaign title (e.g., `Potential Campaign: Target Brand Impersonation Cluster`).
- `status`: `NEW`, `ACTIVE`, `REVIEW`, `CLOSED`.
- `confidence`: `LOW`, `MEDIUM`, `HIGH` (clearly documented, evidence-based scale; never probability of attacker identity).
- `confidence_score`: 0–100 integer representing cumulative evidentiary weight.
- `case_count`: Number of linked cases.
- `email_count`: Number of linked emails.
- `ioc_count`: Total distinct observables in campaign.
- `first_observed_at`: ISO UTC timestamp of earliest observed evidence.
- `last_observed_at`: ISO UTC timestamp of latest observed evidence.
- `explanation`: Deterministic natural language summary explaining why items are correlated.
- `evidence_summary`: Breakdown of correlated features (shared Reply-To, shared domains, etc.).
- `created_at`, `updated_at`: Timestamps.

### B. Campaign Relationships (Graph Foundation)
- Node types: `CAMPAIGN`, `CASE`, `EMAIL`, `DOMAIN`, `IP`, `URL`, `EMAIL_ADDRESS`, `REPLY_TO`, `MESSAGE_ID_DOMAIN`.
- Edge types: `INCLUDES_CASE`, `INCLUDES_EMAIL`, `OBSERVED_IOC`, `SHARED_INFRASTRUCTURE`, `SHARED_IDENTITY`.
- Edge attributes: `strength` (`STRONG`, `MEDIUM`, `WEAK`), `signal`, `observed_at`.

### C. Campaign Timeline Events
- Chronological timeline tracking each observable event (e.g. "2026-09-01: Email ingested", "2026-09-02: Same Reply-To observed in Case ANV-2026-0002", "Confidence updated from MEDIUM to HIGH").

---

## 4. Deterministic Correlation Logic
### A. Normalization Pipeline
1. **Email Addresses (`normalize_email`)**:
   - Strip whitespace, brackets, display names (`John Doe <attacker@evil.com>` -> `attacker@evil.com`).
   - Lowercase domain portion while preserving case-insensitive local part.
2. **Domains (`normalize_domain`)**:
   - Strip leading/trailing whitespace and dots.
   - Lowercase string.
   - Handle IDNA/punycode decoding/encoding consistently (`xn--...`).
3. **URLs (`normalize_url`)**:
   - Strip protocol fragments and query trackers if generic.
   - Lowercase scheme and hostname, preserve path.
   - Extract domain/host independently for correlation matching.
4. **IP Addresses (`normalize_ip`)**:
   - Parse via Python `ipaddress.ip_address` into canonical IPv4/IPv6 format.
5. **Subjects (`normalize_subject`)**:
   - Strip repeated email prefixes: `RE:`, `FW:`, `FWD:`, `AW:`, `SV:`, `[EXTERNAL]`.
   - Normalize whitespace and lowercase.

### B. Signals, Weights & Thresholds
| Category | Signal | Weight | Strength | Condition / False Positive Protection |
| :--- | :--- | :--- | :--- | :--- |
| Infrastructure | `EXACT_SUSPICIOUS_DOMAIN` | +35 | STRONG | Match on non-whitelisted observable domain |
| Infrastructure | `EXACT_IOC_OVERLAP` | +30 | STRONG | Match on exact malicious/suspicious URL or non-cloud IP |
| Infrastructure | `EXACT_PUBLIC_IP` | +25 | STRONG | Match on public origin IP (excluded if shared cloud provider) |
| Identity | `EXACT_REPLY_TO` | +35 | STRONG | Match on non-generic normalized Reply-To address |
| Identity | `EXACT_SENDER` | +20 | MEDIUM | Match on normalized sender address |
| Identity | `EXACT_MSG_ID_DOMAIN` | +15 | MEDIUM | Match on non-public-freemail Message-ID domain |
| Content | `SUBJECT_SIMILARITY` | +15 | MEDIUM | Normalized subject token overlap / Levenshtein $\ge 85\%$ |
| Content | `SUSPICIOUS_PHRASE` | +10 | WEAK-MED | Overlapping financial BEC / credential urgency triggers |
| Threat / Lookalike | `SAME_LOOKALIKE_TARGET` | +25 | STRONG | Model 3B detection of same targeted brand |
| Temporal | `TEMPORAL_PROXIMITY` | +10 | SUPPORT | Ingestion timestamps within 14 days of each other |
| Shared Cloud / ISP | `SHARED_CLOUD_OR_ASN` | +0 (or +2 max) | WEAK | **Strict Guard**: Google, M365, AWS, Cloudflare, generic ISPs alone NEVER cause a correlation! |

### C. Campaign Correlation Scoring Thresholds
- **Correlation Score $\ge 50$**: Emails/Cases are deemed related to the same campaign.
- **Confidence Rating**:
  - `HIGH`: Score $\ge 75$ (Multiple strong infrastructure or identity overlaps).
  - `MEDIUM`: Score $50 - 74$ (Strong Reply-To or domain overlap + content similarity).
  - `LOW`: Score $< 50$ (Insufficient observable evidence; NOT grouped into a campaign).

---

## 5. False-Positive Protections
The system explicitly checks against common infrastructure and public freemail providers:
- Freemail domains (`gmail.com`, `yahoo.com`, `outlook.com`, `hotmail.com`, `protonmail.com`, etc.): Never correlate based solely on sender domain or Message-ID domain.
- Cloud providers & CDNs (`MICROSOFT_365_OR_AZURE`, `GOOGLE_WORKSPACE_OR_GCP`, `AMAZON_WEB_SERVICES`, `CLOUDFLARE`, etc.): Shared hosting/ASN/IP alone provides 0 correlation score towards campaign formation.
- Public recursive resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`): Excluded from IP correlation.

---

## 6. Attribution Boundary Preservation (Forensic Safety)
- The Campaign Intelligence layer is an orthogonal evidence correlation layer.
- It MUST NOT alter:
  - `origin_confidence`
  - `actor_identity` (remains strictly `NOT ESTABLISHED`)
  - `probable_origin_ip`
  - `spf_status`, `dkim_status`, `dmarc_status`
- The system must explicitly label all findings as "Potential Campaign" and "Related Activity", never "Same Attacker" or "Attacker Identified".

---

## 7. API Changes
- `GET /api/v1/campaigns`: List campaigns with status, confidence, case counts, IOC counts, and summary.
- `GET /api/v1/campaigns/{campaign_id}`: Detailed campaign dossier, confidence breakdown, evidence summary, explanation, and chronological timeline.
- `GET /api/v1/campaigns/{campaign_id}/relationships`: Full relationship graph structure (nodes: Campaign, Cases, Emails, Observables; edges: correlation reasons and strengths).
- `POST /api/v1/campaigns/correlate`: On-demand correlation analysis comparing two cases or an incoming email payload against existing campaigns.

---

## 8. Frontend & Mobile Touchpoints
- **Web (`InvestigationWorkspace.tsx`)**:
  - Add "Campaign Intelligence" card to the primary assessment summary.
  - Displays: "Potential Campaign: ANV-26-CMP-XXXX", Confidence Badge (`HIGH`/`MEDIUM`), Related Cases count, and explanation of correlation reasons.
  - "View Campaign Dossier" button opening a focused campaign inspection view.
- **Mobile (`CasesScreen.tsx`)**:
  - Add operational campaign indicators on case cards showing campaign ID, confidence level, and related case count.

---

## 9. Testing Requirements (18 Mandatory Scenarios)
1. Exact same domain overlap -> Correlated (`HIGH` or `MEDIUM` confidence).
2. Exact same Reply-To overlap -> Correlated (`HIGH` confidence).
3. Same suspicious IOC -> Correlated.
4. Highly similar subjects with stripped prefixes (`RE:`, `FW:`) -> Contributes to correlation.
5. Same Gmail infrastructure only -> NOT correlated (False positive guard).
6. Same Microsoft 365 infrastructure only -> NOT correlated (False positive guard).
7. Same ASN / Cloud provider only -> NOT correlated (Weight insufficient).
8. Different unrelated emails -> NOT correlated (`score < 50`, `campaign_id = null`).
9. Campaign confidence calculation adheres to LOW / MEDIUM / HIGH scale.
10. Correlation explanation is deterministic and natural.
11. Campaign creation occurs automatically when sufficient evidence exists.
12. Campaign attachment links subsequent related cases correctly.
13. Timeline ordering reflects real evidence timestamps.
14. Original evidence (raw headers, hashes) remains completely unchanged.
15. Attribution boundary remains invariant (`actor_identity = NOT ESTABLISHED`).
16. Existing Model 1 behavior unchanged (Phishing hash: `f49c153...`).
17. Existing Model 2 behavior unchanged (BEC hash: `afae6a3...`).
18. Existing Model 3B behavior unchanged (Lookalike hash: `31224d6...`).

---

## 10. Files to Create / Modify
- **New Files**:
  - `backend/app/services/campaign_service.py`: Normalization, deterministic correlation scoring, campaign creation, relationship graph building, and timeline assembly.
  - `backend/tests/test_campaign_intelligence.py`: Comprehensive test suite covering all 18 scenarios.
  - `PHASE8A_CAMPAIGN_INTELLIGENCE_REPORT.md`: Comprehensive final documentation report.
- **Modified Files**:
  - `backend/app/database/supabase_client.py`: Update `update()` method and local cache tracking for campaigns and campaign events.
  - `backend/app/api/v1/endpoints/campaigns.py`: Implement complete list, get, relationships, and correlate endpoints.
  - `backend/app/api/v1/endpoints/emails.py`: Hook campaign correlation into `analyze_email` ingestion flow and return campaign intelligence.
  - `backend/app/api/v1/endpoints/cases.py`: Enrich `get_case_details` with correlated campaign information.
  - `web/src/pages/InvestigationWorkspace.tsx`: Display campaign association card and correlation reasons.
  - `mobile/src/screens/CasesScreen.tsx`: Expose campaign badge and operational correlation summary.
