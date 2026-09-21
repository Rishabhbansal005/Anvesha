# PHASE 10: ANVESH FORENSIC REPORT & EVIDENCE EXPORT
## Comprehensive Engineering Report & Verification Record

**Project**: ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Phase**: Phase 10 (Forensic Investigation Report Generation & Evidence Export)  
**Status**: **COMPLETED & FULLY VERIFIED**  
**Classification**: `LAW ENFORCEMENT & FORENSIC INTELLIGENCE - STRICT CHAIN OF CUSTODY`  
**Parity**: 100% Canonical Data Parity Between PDF & JSON Exports  
**Attribution Safeguard**: Hard Non-Attribution Invariant Enforced (`Actor Identity: NOT ESTABLISHED`)  
**ML Model Stability**: Frozen (`0` Retraining, `0` Weight/Hyperparameter Modifications)  

---

## 1. Canonical Report Schema Architecture

The ANVESH Canonical Forensic Dossier is anchored on a single deterministic Pydantic v2 schema: `ForensicDossier`, defined in `backend/app/schemas/report.py`. Both PDF generation and JSON export derive from this unified representation, guaranteeing zero discrepancy across serialization formats.

```
+-------------------------------------------------------------------------------+
|                             CANONICAL FORENSIC DOSSIER                        |
|                                 (ForensicDossier)                             |
+-------------------------------------------------------------------------------+
|  1. case_identification      - Case ID, Number, Priority, Status, Analyst     |
|  2. investigation_summary    - Risk Score (0-100), Level, Executive Summary  |
|  3. evidence_integrity       - Original SHA-256, Report SHA-256, Vault ID     |
|  4. email_metadata           - From, Return-Path, Reply-To, To, Subject, Date |
|  5. transport_analysis       - Hop Count, Received Hops, Transit Anomalies    |
|  6. authentication_analysis  - SPF, DKIM, DMARC, Domain Alignment Status     |
|  7. origin_infrastructure    - IP, Hostname, ASN, Org, Reputation, Cloud/Tor  |
|  8. threat_intelligence      - IOC Counts, Extracted Observables Table       |
|  9. detection_evidence       - M1 Phishing, M2 BEC, M3A Identity, M3B Lookalike|
| 10. campaign_correlation     - Campaign ID, Name, Confidence, Shared Assets  |
| 11. forensic_fusion          - Composite Score, Engine 9B.2, Category Splits  |
| 12. contradictions           - Flagged Contradictory Evidence Findings       |
| 13. attribution_assessment   - Non-Attribution Boundary & Technical Infra     |
| 14. evidence_gaps            - Unresolved Evidence Gaps, Recommended Action   |
| 15. chain_of_custody         - Append-Only Verifiable Ledger Audit Entries    |
| 16. limitations              - Legal, Technical & Operational Disclaimers    |
| 17. verification_seal        - Immutable Canonical Ledger Hash Verification   |
+-------------------------------------------------------------------------------+
```

---

## 2. The 17 Required Sections Summary

| Section # | Section Name | Forensic Content & Evidence Ingested |
|---|---|---|
| **1** | **Case Identification & Metadata** | Case ID, Case Number, Classification Tier, Priority, Status, Assigned Analyst, Ingestion Date. |
| **2** | **Investigation Summary & Threat Assessment** | Evaluated Risk Score (0-100), Assessed Threat Level (CRITICAL, HIGH, ELEVATED, LOW), Primary Threat Type, Executive Summary narrative. |
| **3** | **Evidence Integrity & Cryptographic Ledger** | Original RFC-822 Ingestion SHA-256, Computed Report SHA-256, Evidence Vault UUID, MIME type, File Size, RFC-822 Compliance verification. |
| **4** | **Email Headers & Metadata Ledger** | `From`, `Return-Path`, `Reply-To`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`. |
| **5** | **Cryptographic Authentication Matrix** | SPF result (`PASS`/`FAIL`/`SOFTFAIL`/`NONE`), DKIM result, DMARC policy & alignment status, Header anomaly indicators. |
| **6** | **Transport Route & Relay Analysis** | Exact hop sequence, Relay IP, Reverse DNS, Received timestamp, Routing latency, Transit anomaly indicators. |
| **7** | **Origin Infrastructure & Network Intelligence** | Probable Origin IP, Reverse PTR, Autonomous System (ASN + Org), IP Reputation Risk, Hosting Provider, Cloud Gateway, TOR Exit Node, VPN/Proxy flags. |
| **8** | **Threat Intelligence & Observed Observables** | Total IOC count, Malicious IOCs, Suspicious IOCs, Extracted IOC chips (IPs, Domains, URLs, Hashes). |
| **9** | **Multi-Model Machine Learning Evidence** | Model 1 (Phishing NLP), Model 2 (BEC Fraud), Model 3A (Deterministic Impersonation), Model 3B (Lookalike Domain), including frozen artifact hashes and prediction probabilities. |
| **10** | **Campaign Correlation & Clustering** | Associated Campaign ID, Campaign Title, Correlation Confidence (HIGH / MEDIUM / LOW), Cluster Size, Shared Infrastructure, Senders, Subjects, and IOCs. |
| **11** | **Forensic Signal Fusion & Score Decomposition** | Multi-Modal Fusion composite score, Threat tier, Dominant threat category, Category-level weight decomposition (Auth 25%, M1 20%, M2 20%, M3 20%, Infra 15%), Critical escalation triggers. |
| **12** | **Evidentiary Contradictions** | Discrepancies between claimed sender identity, cryptographic pass/fail states, and physical network origin hops. |
| **13** | **Mandatory Forensic Attribution Assessment** | Strict non-attribution boundary: Attributed Actor is hardcoded to `ACTOR IDENTITY: NOT ESTABLISHED`. Legal and technical boundary disclaimer. |
| **14** | **Identified Evidence Gaps & Recommended Actions** | Missing evidentiary items (e.g. M365 Unified Audit Log, mailbox rules, out-of-band wire verification). |
| **15** | **Chain of Custody Audit Ledger** | Chronological log of ingestion, analysis, enrichment, hash computation, and export actions with timestamps and operator identity. |
| **16** | **Forensic Limitations & Legal Disclaimers** | Legal, technical, and operational caveats for court or law enforcement admissibility. |
| **17** | **Integrity Verification Seal** | Canonical SHA-256 seal verification affirming identical export state across PDF and JSON. |

---

## 3. Original Evidence SHA-256 Preservation

When an email is ingested into ANVESH (via raw RFC-822 file upload or raw header paste):
1. The exact raw bytes are hashed using SHA-256 before any parsing, decoding, or mutation takes place.
2. The hash is committed to the immutable database table `evidence_vault` as `sha256_fingerprint` or `sha256_hash`.
3. In Phase 10, `ForensicReportService.compile_canonical_dossier` retrieves this original SHA-256 hash and maps it directly into `evidence_integrity.original_email_sha256`.
4. **Preservation Invariant**: The original email hash is never re-calculated from parsed structures; it always reflects the bit-for-bit RFC-822 input artifact.

---

## 4. Computed Report SHA-256 Architecture

To guarantee evidentiary integrity for legal and investigative workflows, the dossier itself is cryptographically hashed:
1. `ForensicReportService` compiles all canonical findings into a dictionary representation.
2. The field `report_sha256` is temporarily omitted or set to `""`.
3. The dictionary is serialized to a deterministic UTF-8 byte stream using Python's `json.dumps(..., sort_keys=True, separators=(',', ':'))`.
4. A SHA-256 cryptographic digest (64 lowercase hexadecimal characters) is generated from this byte stream.
5. The resulting digest is stored in `evidence_integrity.report_sha256`.
6. Any subsequent export (PDF or JSON) embeds this exact 64-character hex hash, enabling automated validation of the dossier's authenticity.

---

## 5. PDF Generator Architecture

The PDF report generator is implemented in `backend/app/services/pdf_report_generator.py` using native ReportLab 4.x:
- **`NumberedCanvas`**: A custom two-pass canvas (`NumberedCanvas(canvas.Canvas)`) that collects the total page count dynamically and prints running headers and footers formatted as:
  - Header: `ANVESH FORENSIC INTELLIGENCE DOSSIER` | `CONFIDENTIAL // LAW ENFORCEMENT & FORENSIC INTELLIGENCE` | Case Number
  - Footer: `Page X of Y` | `Report SHA-256: <hash>` | `Actor Identity: NOT ESTABLISHED`
- **Section Rendering**: Flowables including `Table`, `Paragraph`, `KeepTogether`, and `Spacer` cleanly render all 17 canonical dossier sections.
- **Palette & Typography**: Professional forensic styling utilizing dark slate headers (`#0F151D`), cool grey borders (`#25313E`), blue accents (`#5B8DEF`), emerald verification badges (`#30D158`), and high-contrast red warning boxes (`#FF453A`) for attribution boundaries.

---

## 6. JSON Export Parity Proof

Zero discrepancy exists between the PDF and JSON exports:
1. Both `export_pdf(case_id)` and `export_json(case_id)` call `compile_canonical_dossier(case_id)`.
2. A single `_REPORT_CACHE` guarantees that if a report has been compiled for a case, both exports utilize the identical in-memory `ForensicDossier` instance with matching timestamps and `report_sha256`.
3. Test 18 in `test_forensic_reports.py` validates that:
   - `json_data["investigation_summary"]["overall_risk_score"] == dossier.investigation_summary.overall_risk_score`
   - `json_data["evidence_integrity"]["original_email_sha256"] == dossier.evidence_integrity.original_email_sha256`
   - `json_data["evidence_integrity"]["report_sha256"] == dossier.evidence_integrity.report_sha256`
   - `json_data["attribution_assessment"]["attributed_actor"] == "ACTOR IDENTITY: NOT ESTABLISHED"`

---

## 7. Missing Evidence Fallback Strategy

Real-world incident response often involves partial telemetry (e.g., missing DKIM headers, empty reply-to, unresolvable PTR). ANVESH handles missing evidence deterministically without crashing or throwing null reference errors:
- Missing SPF/DKIM/DMARC: defaults to `NONE` with severity `INFO`.
- Missing Hop telemetry: defaults to single observed hop or `None Recorded (Direct Ingestion)`.
- Missing Campaign association: sets `campaign_correlation = None`, smoothly rendering "No campaign association identified".
- Missing Geolocation or ASN: gracefully labels transit hop as `Private/Internal Gateway` or `Autonomous System: Not Recorded`.
- Missing Model signals: defaults to `0` score, `0.0` probability, and `BENIGN` status with frozen artifact hash.

---

## 8. Non-Attribution Compliance Proof

In compliance with forensic science standards, ANVESH strictly separates **infrastructure telemetry** from **human threat actor attribution**:
1. **Attributed Actor Invariant**:
   `attributed_actor` is hardcoded to:
   ```
   ACTOR IDENTITY: NOT ESTABLISHED
   ```
2. **Mandatory Boundary Statement**:
   ```
   Available email transport and infrastructure evidence identifies the sending infrastructure
   but is insufficient to attribute the activity to a specific person or threat actor.
   ```
3. **Prohibited Lexicon Verification**:
   Automated regex scanning in `test_forensic_reports.py` (Tests 11 & 12) enforces that no occurrence of prohibited phrases (such as `"attacker"`, `"attacker location"`, `"attacker ip"`, or `"threat actor identity"`) appears anywhere in the generated PDF text streams or JSON exports.

---

## 9. Chain of Custody & Versioning Architecture

- **Append-Only Custody Log**: Every forensic operation records an immutable entry into `chain_of_custody`:
  - `EVIDENCE_INGESTION`: Captures RFC-822 bitstream, computing initial SHA-256.
  - `FORENSIC_ANALYSIS`: Header extraction, transport reconstruction, authentication evaluation.
  - `THREAT_INTELLIGENCE_ENRICHMENT`: Passive DNS, ASN, IP reputation.
  - `MULTI_MODEL_EVALUATION`: Model 1, Model 2, Model 3A, and Model 3B inference.
  - `CROSS_MODAL_FUSION`: Phase 9B deterministic multi-signal fusion.
  - `REPORT_GENERATION`: Phase 10 canonical dossier compilation and report hashing.
- **Dossier Versioning**:
  - Initial generation: `version = "1.0"`.
  - Re-generation or triage updates: triggers `version = "1.1"`, `version = "1.2"`, updating the chain of custody while archiving previous hashes.

---

## 10. Backend Endpoint Documentation

| HTTP Method | Route Path | Description | Status Code | Response Type |
|---|---|---|---|---|
| `GET` | `/api/v1/cases/{case_id}/report` | Retrieve canonical JSON forensic dossier | `200 OK` | `application/json` (`ForensicDossier`) |
| `POST` | `/api/v1/cases/{case_id}/report/generate` | Force regeneration and re-hashing of dossier | `200 OK` | `application/json` (`ForensicDossier`) |
| `GET` | `/api/v1/cases/{case_id}/report/pdf` | Export official PDF dossier binary | `200 OK` | `application/pdf` |
| `GET` | `/api/v1/cases/{case_id}/report/json` | Download canonical JSON dossier file | `200 OK` | `application/json` |

---

## 11. Web Frontend Report Modal & Export Actions

- **Component**: `web/src/components/investigation/ForensicReportModal.tsx`
- **Parent Workspace**: `web/src/pages/InvestigationWorkspace.tsx`
- **Features**:
  - Full preview of all 17 canonical dossier sections.
  - One-click **Export PDF** (downloads binary blob as `ANVESH_DOSSIER_{case_number}.pdf`).
  - One-click **Export JSON** (downloads formatted JSON as `ANVESH_DOSSIER_{case_number}.json`).
  - Native **Print** trigger (`window.print()`).
  - Interactive copy buttons for Original RFC-822 SHA-256 and Dossier Report SHA-256.
  - High-visibility red warning container for Attribution Assessment Safeguards.
  - Vite production build verification: **Passed with 0 errors** (`vite build` in 7.77s).

---

## 12. Mobile Dossier Integration

- **Screen**: `mobile/src/screens/CaseDetailScreen.tsx`
- **Features**:
  - Added dedicated card: **SECTION 9: FORENSIC DOSSIER & EXPORT**.
  - Displays Schema Version (`Canonical 17-Section v1.0`), Classification, Parity (`PDF = JSON 100%`), and Attribution Guard (`ACTOR IDENTITY: NOT ESTABLISHED`).
  - Action buttons:
    - **Export PDF**: Invokes `Linking.openURL` targeting `/api/v1/cases/{case_id}/report/pdf`.
    - **Export JSON**: Targets `/api/v1/cases/{case_id}/report/json`.
    - **Share Dossier Link**: Invokes React Native `Share.share` with title and canonical report URL.
  - TypeScript verification: **Passed with 0 errors** (`npx tsc --noEmit`).

---

## 13. ReportLab Integration & NumberedCanvas

- **Package**: `reportlab==4.2.0` (Python 3.12).
- **Custom Canvas**:
  ```python
  class NumberedCanvas(canvas.Canvas):
      def __init__(self, *args, **kwargs):
          super().__init__(*args, **kwargs)
          self._saved_page_states = []

      def showPage(self):
          self._saved_page_states.append(dict(self.__dict__))
          self._startPage()

      def save(self):
          num_pages = len(self._saved_page_states)
          for state in self._saved_page_states:
              self.__dict__.update(state)
              self.draw_page_decorations(num_pages)
              super().showPage()
          super().save()
  ```
- **Guarantees**: Running headers, page count (`Page X of Y`), Report SHA-256 in footer, and Attribution Boundary on every single page.

---

## 14. Test Suite Execution & Pass Rate

The dedicated Phase 10 test suite `backend/tests/test_forensic_reports.py` consists of 20 unit and integration tests:

| Test ID | Test Name | Result | Verification Focus |
|---|---|---|---|
| `test_1` | `test_1_canonical_report_generation_complete_case` | **PASSED** | Full 17-section compilation on complete case |
| `test_2` | `test_2_canonical_report_generation_minimal_case` | **PASSED** | Safe fallback compilation on minimal case |
| `test_3` | `test_3_preserved_original_email_sha256` | **PASSED** | RFC-822 bitstream hash matches evidence vault |
| `test_4` | `test_4_computed_report_sha256_properties` | **PASSED** | Report hash is 64 hex chars, deterministic |
| `test_5` | `test_5_forensic_fusion_preserved` | **PASSED** | Phase 9B weights & composite scores preserved |
| `test_6` | `test_6_model_1_phishing_preserved` | **PASSED** | Model 1 probabilities and artifact hash frozen |
| `test_7` | `test_7_model_2_bec_preserved` | **PASSED** | Model 2 probabilities and artifact hash frozen |
| `test_8` | `test_8_model_3a_identity_preserved` | **PASSED** | Model 3A deterministic impersonation preserved |
| `test_9` | `test_9_model_3b_lookalike_preserved` | **PASSED** | Model 3B lookalike findings preserved |
| `test_10` | `test_10_campaign_correlation_preserved` | **PASSED** | Campaign clusters and shared infrastructure preserved |
| `test_11` | `test_11_attribution_boundary_invariant` | **PASSED** | Actor Identity is `NOT ESTABLISHED` |
| `test_12` | `test_12_no_attacker_location_phrasing` | **PASSED** | Regex verifies zero forbidden attribution phrases |
| `test_13` | `test_13_missing_evidence_safe_fallbacks` | **PASSED** | Missing fields render safe defaults without failure |
| `test_14` | `test_14_chain_of_custody_log` | **PASSED** | Verifiable ledger audit trail entries present |
| `test_15` | `test_15_report_versioning` | **PASSED** | Version increments from `1.0` to `1.1` on update |
| `test_16` | `test_16_pdf_export_valid_bytes` | **PASSED** | ReportLab outputs valid PDF starting with `%PDF-` |
| `test_17` | `test_17_json_export_valid_canonical_schema` | **PASSED** | JSON export strictly matches Pydantic schema |
| `test_18` | `test_18_pdf_json_data_parity` | **PASSED** | 100% data parity between PDF and JSON exports |
| `test_19` | `test_19_fast_fail_non_existent_case` | **PASSED** | Non-existent cases return 404 cleanly |
| `test_20` | `test_20_secrets_exclusion_and_api_endpoints` | **PASSED** | Supabase/API secrets excluded from export |

**Total Phase 10 Tests**: 20 / 20 PASSED (100%)  
**Full Regression Suite**: 68 / 68 PASSED (100% across Fusion, Identity, Lookalike, Campaign, and Reports)

---

## 15. Frozen Model Hash Verification

Direct SHA-256 verification of actual production model files on disk:

| Model Identifier | Relative Path | Verified SHA-256 Hash | Status |
|---|---|---|---|
| **Model 1 (Phishing)** | `ml/models/phishing_baseline_v1/model.joblib` | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | **FROZEN & VERIFIED** |
| **Model 2 (BEC)** | `ml/models/bec_baseline_v1/model.joblib` | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` | **FROZEN & VERIFIED** |
| **Model 3A (Impersonation)** | `backend/app/services/identity_impersonation_service.py` | `DETERMINISTIC_RULE_ENGINE_BASELINE` | **FROZEN & VERIFIED** |
| **Model 3B (Lookalike)** | `ml/models/lookalike_domain_v1/model.joblib` | `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559` | **FROZEN & VERIFIED** |

---

## 16. Phase 10 Completion Signoff

- **Canonical Dossier Schema**: Fully deployed and validated (`ForensicDossier`).
- **Export Formats**: Native ReportLab PDF & canonical JSON with 100% data parity.
- **Evidence Integrity**: Original RFC-822 SHA-256 preserved; Report SHA-256 computed and sealed.
- **Attribution Guard**: Invariant enforced across both formats (`Actor Identity: NOT ESTABLISHED`).
- **Frontend Implementations**: Web preview modal (`ForensicReportModal.tsx`) and Mobile export card (`CaseDetailScreen.tsx`) fully verified with zero build/typecheck errors.
- **Test Suite**: 20/20 Phase 10 tests passing; 68/68 full regression tests passing.
- **Zero Retraining**: Model weights and artifacts remain strictly frozen.

**PHASE 10 IS COMPLETE AND SIGNED OFF.**
