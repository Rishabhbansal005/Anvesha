# PHASE 11: ANVESH CASE MANAGEMENT & ANALYST WORKFLOW
## Engineering Report & Operational Verification Record

**Project**: ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Phase**: Phase 11 (Case Management & Analyst Workflow)  
**Status**: **COMPLETED & FULLY VERIFIED**  
**Core Lifecycle**: `ALERT → CASE → TRIAGE → INVESTIGATION → ANALYST DECISION → ESCALATION/RESOLUTION → CLOSURE`  
**System Assessment vs Analyst Adjudication**: Strictly decoupled (`risk_score`, `risk_level`, `confidence` remain immutable)  
**Attribution Boundary Safeguard**: Hard non-attribution invariant enforced across all workflows (`Actor Identity: NOT ESTABLISHED`)  
**ML Model Stability**: 100% Frozen (0 retraining, 0 weight modifications, identical artifact hashes)  
**Test Suite**: 20/20 Phase 11 tests passed | 88/88 Full platform regression tests passed  

---

## 1. Executive Summary

Phase 11 transitions ANVESH from a reactive detection engine into an **active, law-enforcement-grade Security Operations Center (SOC) investigation platform**. 

Prior to Phase 11, automated threat scores, header analysis, ML models, and campaign correlations generated isolated case records. Phase 11 formalizes the end-to-end investigation lifecycle:
- Controls status transitions via an explicit state machine.
- Enforces strict role-based authentication without hallucinated/fictional identities.
- Preserves automated system ground truth (`risk_score`) as immutable evidence while capturing human analyst adjudications (`CONFIRMED_THREAT`, `BENIGN_FALSE_POSITIVE`, `NEEDS_MORE_EVIDENCE`).
- Records append-only forensic notes and unified chronological activity timelines for court-admissible auditability.
- Provides unified web workspace controls and mobile on-call companion capabilities with complete attribution boundary protection.

---

## 2. System State Machine & Allowed Transitions

Case status progression is governed by `ALLOWED_STATUS_TRANSITIONS` defined in `backend/app/core/constants.py`:

```
               +-------------------------------------------------------------+
               |                                                             |
               v                                                             |
            [ NEW ] ------------------------------> [ TRIAGED ]              |
               |                                         |                   |
               +-------------------+                     |                   |
                                   |                     v                   |
                                   +-------------> [ INVESTIGATING ] <-------+ (Reopen)
                                                     |        ^
                                        +------------+        |
                                        | (Escalate)          | (De-escalate)
                                        v                     |
                                  [ ESCALATED ] --------------+
                                        |
                                        | (Resolve)
                                        v
                                  [ RESOLVED ]
                                        |
                                        | (Close)
                                        v
                                   [ CLOSED ] (LOCKED)
                                        |
                                        +-----> (Reopen via INVESTIGATING)
```

### Transition Rules Table

| Current Status | Allowed Target Statuses | Validation / Enforcement Rules |
|---|---|---|
| `NEW` | `TRIAGED`, `INVESTIGATING`, `ESCALATED`, `RESOLVED` | Ingestion status; auto-transitions or analyst triage. |
| `TRIAGED` | `INVESTIGATING`, `ESCALATED`, `RESOLVED` | Initial review completed; can move to active investigation or escalate. |
| `INVESTIGATING` | `ESCALATED`, `RESOLVED`, `CLOSED` | Active deep-dive by assigned analyst. |
| `ESCALATED` | `INVESTIGATING`, `RESOLVED` | High-priority escalation; can de-escalate or directly resolve. |
| `RESOLVED` | `CLOSED`, `INVESTIGATING` | Resolution recorded; can close or reopen if new evidence appears. |
| `CLOSED` | `INVESTIGATING` | Locked against all edits; reopening transitions to `INVESTIGATING`. |

**Backward Compatibility**: Legacy statuses (`IN_PROGRESS`, `UNDER_REVIEW`, `FALSE_POSITIVE`) are mapped and accepted transparently.

---

## 3. Separation of Automated System Assessment vs Human Analyst Decision

A foundational invariant of Phase 11 is the strict architectural separation between **Sensor Ground Truth** and **Analyst Adjudication**:

```
+------------------------------------------+    +------------------------------------------+
|      AUTOMATED SYSTEM ASSESSMENT         |    |            ANALYST DECISION              |
|        (Immutable Ground Truth)          |    |          (Human Adjudication)            |
+------------------------------------------+    +------------------------------------------+
| • risk_score: 82/100 (HIGH)              |    | • analyst_decision: CONFIRMED_THREAT     |
| • threat_type: CREDENTIAL_PHISHING       |    | • analyst_decision_reason: "Credential  |
| • origin_confidence: HIGH                |    |   harvesting landing page verified on    |
| • probable_origin_ip: 194.26.29.112      |    |   compromised hosting infrastructure."   |
| • ML Model Scores (M1, M2, M3A, M3B)     |    | • analyst_decision_by: analyst_usr_902   |
|                                          |    | • analyst_decision_at: 2026-09-01T10:30Z |
| [LOCKED: Sensor scores are NEVER         |    |                                          |
|  overwritten by analyst decision]        |    | [Decisions are versioned in ledger]      |
+------------------------------------------+    +------------------------------------------+
```

### Decision Types
1. `CONFIRMED_THREAT`: Analyst validates malicious intent (BEC, Phishing, Impersonation).
2. `BENIGN_FALSE_POSITIVE`: Analyst validates legitimate communication or sensor FP.
3. `NEEDS_MORE_EVIDENCE`: Telemetry is inconclusive; additional logs/evidence needed.
4. `PENDING`: Initial unadjudicated state.

Both states are concurrently exported in canonical dossiers, forensic reports, and API payloads without collision.

---

## 4. Append-Only Forensic Notes Ledger

Forensic notes preserve investigative hypotheses, witness interviews, and technical findings:
- **Append-Only Invariant**: Once created, notes cannot be updated, deleted, or reordered.
- **Custody Fields**: Each note captures `id` (UUID), `case_id`, `author_id`, `author_email`, `content`, and `created_at` (UTC).
- **Closed-Case Guard**: Notes cannot be appended to `CLOSED` cases unless explicitly reopened.

---

## 5. Escalation & Resolution Workflows

### Escalation Workflow
- **Endpoint**: `POST /api/v1/cases/{case_id}/escalate`
- **Requirements**: Non-empty `escalation_reason` (minimum 5 characters).
- **Actions**:
  - Updates status to `ESCALATED`.
  - Sets `escalation_reason` on the case record.
  - Logs `CASE_ESCALATED` event to the activity timeline with actor attribution.
  - Dispatches on-call alerts to mobile companion endpoints.

### Resolution Workflow
- **Endpoint**: `POST /api/v1/cases/{case_id}/resolve`
- **Requirements**:
  - Valid decision (`CONFIRMED_THREAT` or `BENIGN_FALSE_POSITIVE`).
  - Mandatory `resolution_notes` (minimum 5 characters).
- **Actions**:
  - Updates status to `RESOLVED`.
  - Records the formal decision and resolution rationale.
  - Appends an audit note: `[RESOLUTION NOTE]: ...`.
  - Logs `CASE_RESOLVED` event to the activity timeline.

---

## 6. Closed-Case Lock & Protection

Cases marked as `CLOSED` represent concluded legal/forensic inquiries:
- **Write Lock**: All endpoints (`status`, `assignment`, `decision`, `notes`, `escalate`, `resolve`) reject modifications on `CLOSED` cases with `HTTP 400: Case ... is CLOSED and locked against modifications.`
- **Controlled Reopening**: The ONLY permitted operation on a closed case is transitioning back to `INVESTIGATING` (`PATCH /api/v1/cases/{case_id}/status` with `status: "INVESTIGATING"` and mandatory reopening reason).
- Reopening generates a high-visibility `CASE_REOPENED` audit event.

---

## 7. Unified Chronological Activity Timeline

All system triggers and human actions are consolidated into a unified timeline:

| Event Type | Actor Category | Description Pattern |
|---|---|---|
| `SYSTEM_ALERT` | `SYSTEM` | Email ingested, RFC-822 parsed, threat score computed |
| `STATUS_CHANGE` | `ANALYST` | Status transitioned from `<old>` to `<new>` |
| `ASSIGNMENT_CHANGE` | `ANALYST` | Assigned to `<new_assignee>` (previously `<old_assignee>`) |
| `ANALYST_DECISION` | `ANALYST` | Decision `<decision>` recorded with reason |
| `NOTE_ADDED` | `ANALYST` | Forensic investigation note appended |
| `CASE_ESCALATED` | `ANALYST` | Case escalated: `<reason>` |
| `CASE_RESOLVED` | `ANALYST` | Case resolved as `<decision>`: `<notes>` |
| `CASE_CLOSED` | `ANALYST` | Case closed and locked |
| `CASE_REOPENED` | `ANALYST` | Case reopened from closed state |

Timeline entries feature `[SYSTEM]` vs `[ANALYST]` badges in both web and mobile frontends.

---

## 8. Backend API Endpoints Specification

All endpoints are hosted under `/api/v1/cases`:

```http
PATCH /api/v1/cases/{case_id}/status
Headers: X-Analyst-ID: <analyst_id>
Body: { "status": "TRIAGED" | "INVESTIGATING" | "ESCALATED" | "RESOLVED" | "CLOSED", "note": "..." }

PATCH /api/v1/cases/{case_id}/assignment
Headers: X-Analyst-ID: <analyst_id>
Body: { "assigned_to": "analyst_usr_905" }

POST /api/v1/cases/{case_id}/decision
Headers: X-Analyst-ID: <analyst_id>
Body: { "decision": "CONFIRMED_THREAT" | "BENIGN_FALSE_POSITIVE" | "NEEDS_MORE_EVIDENCE", "reason": "..." }

POST /api/v1/cases/{case_id}/notes
Headers: X-Analyst-ID: <analyst_id>
Body: { "content": "Forensic finding narrative..." }

GET /api/v1/cases/{case_id}/notes
Headers: X-Analyst-ID: <analyst_id>
Response: { "case_id": "...", "total": N, "items": [...] }

POST /api/v1/cases/{case_id}/escalate
Headers: X-Analyst-ID: <analyst_id>
Body: { "escalation_reason": "Active C2 beaconing observed" }

POST /api/v1/cases/{case_id}/resolve
Headers: X-Analyst-ID: <analyst_id>
Body: { "decision": "CONFIRMED_THREAT", "resolution_notes": "Mitigations applied" }

GET /api/v1/cases/{case_id}/activity
Headers: X-Analyst-ID: <analyst_id>
Response: { "case_id": "...", "total": N, "items": [...] }

GET /api/v1/cases?decision=CONFIRMED_THREAT&status=INVESTIGATING
Headers: X-Analyst-ID: <analyst_id>
Response: Filtered list of cases with decision and assignment metadata
```

---

## 9. Database Schema & Migration

Database migration script: `backend/app/database/migrations/phase11_case_workflow.sql`.

### Tables Added / Extended:
1. **`cases` (columns added)**:
   - `analyst_decision VARCHAR(64)`
   - `analyst_decision_reason TEXT`
   - `analyst_decision_at TIMESTAMPTZ`
   - `analyst_decision_by VARCHAR(128)`
   - `escalation_reason TEXT`
2. **`case_notes` (new table)**:
   - `id UUID PRIMARY KEY`, `case_id UUID REFERENCES cases(id)`
   - `author_id VARCHAR(128) NOT NULL`, `author_email VARCHAR(255)`
   - `content TEXT NOT NULL`, `created_at TIMESTAMPTZ DEFAULT NOW()`
3. **`case_decisions` (new table)**:
   - `id UUID PRIMARY KEY`, `case_id UUID REFERENCES cases(id)`
   - `decision VARCHAR(64) NOT NULL`, `reason TEXT NOT NULL`
   - `decided_by VARCHAR(128) NOT NULL`, `created_at TIMESTAMPTZ DEFAULT NOW()`
4. **`case_activities` (new table)**:
   - `id UUID PRIMARY KEY`, `case_id UUID REFERENCES cases(id)`
   - `event_type VARCHAR(64) NOT NULL`, `actor_id VARCHAR(128) NOT NULL`
   - `actor_email VARCHAR(255)`, `description TEXT NOT NULL`
   - `details JSONB`, `created_at TIMESTAMPTZ DEFAULT NOW()`

Indexes created on `case_id` and `created_at` for optimal retrieval.

---

## 10. Authentication & Analyst Identity Policy

- **No Fabricated Identities**: The system strictly records authenticated analyst identifiers (e.g., `analyst_usr_902`, `analyst@anvesh.gov.in`). Fictional names like "John Doe" or generic fallback labels are forbidden.
- **Dependency**: `get_authenticated_analyst` inspects:
  1. `X-Analyst-ID` header
  2. `Authorization: Bearer <token>`
- **Rejection**: Requests without credentials or with empty strings receive `HTTP 401 Unauthorized: Valid analyst credentials required.`

---

## 11. Web Frontend Implementation

### Component Architecture
1. **`AnalystWorkflowPanel.tsx`**:
   - Status badge and dynamic lifecycle transition action bar.
   - Assignee display, "Assign to Me", and custom reassign input.
   - Side-by-side **System Forensic Assessment** (locked) vs **Analyst Adjudication** cards.
   - Decision radio options with mandatory justification and save button.
   - Escalate modal and Resolve modal with required input validation.
   - Append-only notes feed with analyst identity badge.
   - Unified chronological activity timeline with `[SYSTEM]` vs `[ANALYST]` indicators.
2. **`InvestigationWorkspace.tsx`**:
   - Added `'workflow'` tab to `WorkspaceNavSection` with dedicated sidebar icon (`UserCheck`).
   - Integrated `AnalystWorkflowPanel` with live case data and reactive refresh.
3. **`CasesPage.tsx`**:
   - Added full lifecycle status filters (`ALL`, `NEW`, `TRIAGED`, `INVESTIGATING`, `ESCALATED`, `RESOLVED`, `CLOSED`).
   - Added decision filters (`ALL`, `THREAT`, `BENIGN`, `MORE INFO`, `PENDING`).
   - Displays assignee and color-coded decision badges in investigation rows.
4. **`AlertsPage.tsx`**:
   - Linked triage actions directly with case lifecycle status transitions.

**Build Verification**: Clean production build via `npm run build` (`dist/assets/index-BsQdbCib.js` 428 kB, 0 errors).

---

## 12. Mobile Frontend Implementation

### Component Architecture
1. **`CaseDetailScreen.tsx`**:
   - Compact **ANALYST WORKFLOW** card rendered prominently under the dossier header.
   - Quick action buttons: `[Triage]`, `[Investigate]`, `[Escalate]`, `[Resolve]`, `[Close]`, `[Reopen]`.
   - "Assign to Me" one-tap action.
   - Stacked System Truth vs Adjudication preview.
   - Native Modals for Decision, Note, Escalate, and Resolve with touch-optimized controls.
   - Recent notes ledger and activity timeline feed.
2. **`CasesScreen.tsx`**:
   - Horizontal scrolling status filter chips matching Phase 11 lifecycle.
   - Displays status pill, assignee, and decision badges on each card.
3. **`mobile/src/constants/index.ts`**:
   - Exported `DEFAULT_ANALYST` and `getAuthHeaders` helper for authenticated mobile requests.

**Build Verification**: Clean TypeScript check via `npx tsc --noEmit` (0 errors).

---

## 13. Preservation of Attribution Boundary Safeguard

Every workflow component (backend services, web panels, mobile screens, and forensic exports) maintains the strict attribution boundary invariant:
- **Exact String Enforced**: `Actor Identity: NOT ESTABLISHED`.
- Prohibited phrasing ("Guilty actor", "Perpetrator identified", "Origin proves identity") is completely prevented.
- Clear safeguard banners appear at the top of the workflow panel in both web and mobile:
  > *"All escalation, triage, and resolution decisions operate strictly on observable infrastructure, SPF/DKIM authentication telemetry, and content patterns. Individual physical actor identity cannot be established."*

---

## 14. Preservation of Frozen ML Models & Artifact Hashes

Phase 11 introduces **0 ML model modifications**. All production models remain byte-identical:

| Model | Production Artifact Path | SHA-256 Hash | Status |
|---|---|---|---|
| **Model 1 (Phishing NLP)** | `ml/models/production/model1_phishing_pipeline.joblib` | `f49c0d64467c61c775fc4fca4df35eef22f2812ef6539f37b12275681ce26ef6` | **FROZEN** |
| **Model 2 (BEC Fraud)** | `ml/models/production/model2_bec_pipeline.joblib` | `afae86ea3a479a05df82c974917a2db12ebdf2ca8f6cffecfa9b244799047fc5` | **FROZEN** |
| **Model 3A (Identity)** | Deterministic Rules (`identity_impersonation_service.py`) | Deterministic Rule Hashes | **FROZEN** |
| **Model 3B (Lookalike)** | `ml/models/production/lookalike_pipeline.joblib` | `3122c42c234a9193246ebec58c0379c68d22fdfce0743b17c768995a56d953f9` | **FROZEN** |

---

## 15. Test Suite Verification Results

### Phase 11 Test Suite (`backend/tests/test_case_workflow.py`)
All 20 tests pass with 100% success rate:

```
tests/test_case_workflow.py::test_1_valid_status_transition PASSED                    [  5%]
tests/test_case_workflow.py::test_2_invalid_status_transition PASSED                  [ 10%]
tests/test_case_workflow.py::test_3_unauthorized_status_change PASSED                 [ 15%]
tests/test_case_workflow.py::test_4_case_assignment PASSED                            [ 20%]
tests/test_case_workflow.py::test_5_case_reassignment PASSED                          [ 25%]
tests/test_case_workflow.py::test_6_note_creation PASSED                              [ 30%]
tests/test_case_workflow.py::test_7_note_requires_authentication PASSED               [ 35%]
tests/test_case_workflow.py::test_8_analyst_decision_creation PASSED                  [ 40%]
tests/test_case_workflow.py::test_9_analyst_decision_remains_separate_from_system_risk PASSED [ 45%]
tests/test_case_workflow.py::test_10_escalation_workflow PASSED                       [ 50%]
tests/test_case_workflow.py::test_11_escalation_reason_required PASSED                [ 55%]
tests/test_case_workflow.py::test_12_resolution_requires_decision PASSED              [ 60%]
tests/test_case_workflow.py::test_13_closed_case_protection PASSED                    [ 65%]
tests/test_case_workflow.py::test_14_activity_timeline_creation PASSED                [ 70%]
tests/test_case_workflow.py::test_15_authenticated_actor_recorded_correctly PASSED    [ 75%]
tests/test_case_workflow.py::test_16_no_fabricated_analyst_identity PASSED            [ 80%]
tests/test_case_workflow.py::test_17_duplicate_concurrent_decision_handling PASSED     [ 85%]
tests/test_case_workflow.py::test_18_existing_forensic_evidence_remains_intact PASSED  [ 90%]
tests/test_case_workflow.py::test_19_existing_report_generation_remains_intact PASSED  [ 95%]
tests/test_case_workflow.py::test_20_existing_attribution_boundary_remains_intact PASSED [100%]

================================= 20 passed in 7.97s ==================================
```

### Full Regression Suite
```
tests/test_forensic_fusion.py         ... 14 passed
tests/test_identity_impersonation.py  ... 10 passed
tests/test_lookalike_pipeline.py      ... 12 passed
tests/test_campaign_intelligence.py   ... 14 passed
tests/test_forensic_reports.py        ... 18 passed
tests/test_case_workflow.py           ... 20 passed

================================= 88 passed in 49.15s =================================
```

---

## 16. Production Readiness & Sign-Off

Phase 11 is **fully implemented, verified, and production-ready**:
- Backend services, endpoints, schemas, and migrations complete.
- Web frontend build verified and fully functional.
- Mobile app typechecked and equipped with incident workflow controls.
- All attribution boundaries and ML model freezes strictly honored.
- Zero regressions across existing features.

**PHASE 11 COMPLETE — STOPPING HERE.**
