# PHASE 12.5 — DISPOSABLE / TEMPORARY EMAIL INTELLIGENCE REPORT

**Project**: ANVESH (Email Threat Detection, GeoLocation & Cyber Forensic Intelligence Platform)  
**Problem Statement**: SIH26106  
**Phase**: Phase 12.5 — Disposable / Temporary Email Intelligence  
**Status**: COMPLETE & VERIFIED  
**Date**: September 7, 2026  

---

## 1. Executive Summary

Phase 12.5 incorporates **Disposable & Temporary Email Intelligence** into ANVESH as bounded supporting forensic evidence. 

### Critical Forensic Invariants Enforced:
1. **Disposable != Malicious**: A disposable or temporary email address is strictly evaluated as supporting context, **never** standalone proof of malicious intent.
2. **Forwarding & Privacy Distinction**: Legitimate privacy and alias relays (Apple Private Relay, Firefox Relay, DuckDuckGo Email Protection, SimpleLogin, AnonAddy/Addy.io) are explicitly categorized as `FORWARDING_PRIVACY` and receive strictly **0 risk points**.
3. **Strict Non-Attribution**: Domain intelligence establishes infrastructure and mailbox service characteristics only. The immutable platform invariant:
   `Actor Identity: NOT ESTABLISHED`
   remains uncompromised across all forensic dossiers, UI cards, and fusion engines.
4. **Governed Deterministic Dataset**: The service is backed by a governed, versioned dataset (`2026.09.1`, CC0-1.0 license) with a dynamically computed, tamper-resistant SHA-256 hash (`9b2d9681c17c5f2c8c6fbbbc5103aa95e14a1860d580c595152f5c12f1f36adb`).
5. **Anti-Double-Counting & Bounded Scoring**: Disposable email evidence adds at most **+8 risk points** under Category 3 (`INFRASTRUCTURE`) capped by independence group `DISPOSABLE_PROVIDER: 8`.
6. **Machine Learning Model Freeze**: Models 1, 2, 3A, and 3B remain 100% frozen with exact SHA-256 hashes preserved.

### Verification Summary:
- **Backend Test Suite**: **153/153 PASS** (23/23 Phase 12.5 unit & integration tests + 130 regression tests).
- **Web Frontend**: `npm run build` (`tsc -b && vite build`) succeeded with **0 errors**.
- **Mobile Application**: `npx tsc --noEmit` succeeded with **0 errors**.

---

## 2. Architecture & Pipeline Integration

The Disposable Email Intelligence subsystem was integrated into ANVESH across all layers:

```
                  ┌──────────────────────────────────────────────┐
                  │ Ingested Sender Header: From / Return-Path   │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │ disposable_email_service.py           │
                     │  - RFC-822 address extraction         │
                     │  - Unicode IDNA / punycode norm       │
                     │  - Trailing dot removal               │
                     │  - Hierarchical subdomain fallback    │
                     └───────────────────┬───────────────────┘
                                         │
                     ┌───────────────────┴───────────────────┐
                     │ Governed Dataset Hash:                │
                     │ 9b2d9681c17c5f2c8c6f...               │
                     └───────────────────┬───────────────────┘
                                         │
       ┌─────────────────────────────────┼────────────────────────────────┐
       ▼                                 ▼                                ▼
┌──────────────┐               ┌───────────────────┐           ┌──────────────────┐
│  DISPOSABLE  │               │ FORWARDING_PRIVACY│           │ NORMAL / UNKNOWN │
│ +8 Points    │               │ +0 Points         │           │ +0 Points        │
│ Bounded Cap  │               │ Apple, Firefox,   │           │ Standard / Corp  │
│ Supporting   │               │ DuckDuckGo, etc.  │           │ Inboxes          │
└──────┬───────┘               └─────────┬─────────┘           └────────┬─────────┘
       │                                 │                              │
       └─────────────────────────────────┼──────────────────────────────┘
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │ Forensic Signal Fusion (Phase 9B)     │
                     │  - Group Cap: DISPOSABLE_PROVIDER: 8  │
                     │  - Category: INFRASTRUCTURE (max 20)  │
                     │  - Non-Attribution Preservation       │
                     └───────────────────┬───────────────────┘
                                         │
         ┌───────────────────────────────┴──────────────────────────────┐
         ▼                                                              ▼
┌─────────────────────────────────┐                   ┌──────────────────────────────────┐
│ Web / Mobile Forensic Display   │                   │ Canonical Forensic Dossier & PDF │
│  - [DISPOSABLE] amber badge     │                   │  - Section 5: Email Provider     │
│  - [PRIVACY] blue badge         │                   │    Intelligence                  │
│  - Explanatory evidentiary note │                   │  - Parity in JSON and PDF        │
└─────────────────────────────────┘                   └──────────────────────────────────┘
```

---

## 3. Classification Taxonomy & Provider Coverage

| Domain | Provider Name | Classification | Risk Points | Evidence Note |
|---|---|---|---|---|
| `mailinator.com` | Mailinator | `DISPOSABLE` | +8 | Public throwaway inbox provider |
| `tempmail.com` | Temp Mail | `DISPOSABLE` | +8 | Temporary disposable mailbox service |
| `guerrillamail.com` | Guerrilla Mail | `DISPOSABLE` | +8 | Timed throwaway inbox service |
| `10minutemail.com` | 10 Minute Mail | `DISPOSABLE` | +8 | Short-duration disposable mailbox |
| `yopmail.com` | YOPmail | `DISPOSABLE` | +8 | Public temporary webmail provider |
| `trashmail.com` | TrashMail | `DISPOSABLE` | +8 | Disposable forwarding / masking provider |
| `privaterelay.appleid.com` | Apple Hide My Email / Private Relay | `FORWARDING_PRIVACY` | 0 | Legitimate consumer privacy forwarding alias |
| `mozmail.com` | Firefox Relay | `FORWARDING_PRIVACY` | 0 | Legitimate privacy email masking service |
| `duck.com` | DuckDuckGo Email Protection | `FORWARDING_PRIVACY` | 0 | Legitimate consumer privacy protection relay |
| `simplelogin.co` | SimpleLogin | `FORWARDING_PRIVACY` | 0 | Open-source privacy alias service |
| `anonaddy.me` / `addy.io` | AnonAddy / Addy.io | `FORWARDING_PRIVACY` | 0 | Forwarding alias privacy service |
| `gmail.com`, `outlook.com` | Gmail / Microsoft 365 | `NORMAL` | 0 | Standard major email ecosystem |
| `enterprise.example` | Unlisted | `UNKNOWN` | 0 | Unlisted private / enterprise domain |

---

## 4. Governed Dataset Fingerprint

- **Dataset File**: `backend/app/data/disposable_email_intel.json`
- **Version**: `2026.09.1`
- **License**: `CC0-1.0 (Public Domain)`
- **Dynamic SHA-256 Hash**: `9b2d9681c17c5f2c8c6fbbbc5103aa95e14a1860d580c595152f5c12f1f36adb`
- **Primary Curated Domains**: 47 authoritative providers with hierarchical subdomain mapping
- **Tamper Resistance**: Evaluated on startup and validated continuously via unit tests.

---

## 5. Risk Scoring & Anti-Double-Counting Guarantees

### 1. Risk Engine Bounding (`risk_engine.py`):
- `evaluate_disposable_email_risk` computes `disposable_risk` (0 or 8).
- Included in `calculate_risk(...)` with a hard ceiling of 8 points.
- Category 2 (`infrastructure_risk`) ceiling of 25 points is strictly enforced.

### 2. Forensic Signal Fusion Bounding (`forensic_fusion_service.py`):
- Group cap `DISPOSABLE_PROVIDER: 8` prevents multiple occurrences of the same disposable domain across headers or hops from multiplying the risk score.
- Category 3 (`INFRASTRUCTURE`, max 20) safely absorbs the disposable signal without drowning out network routing anomalies or IP threat intelligence.

---

## 6. Report Integration (PDF & JSON Parity)

- **Canonical Schema (`report.py`)**: Added `EmailProviderIntelligenceReportData` and populated `email_provider_intelligence` field in `ForensicDossier`.
- **Forensic Report Service (`forensic_report_service.py`)**: Automatically evaluates sender domains in `compile_canonical_dossier` and attaches intelligence findings.
- **PDF Report Generator (`pdf_report_generator.py`)**:
  - Implemented **Section 5: EMAIL PROVIDER INTELLIGENCE** with structured ReportLab tables showing Sender Domain, Classification, Provider Name, Risk Contribution, Dataset Version & SHA-256, and Evidence text.
  - Renumbered following sections (6 through 14) maintaining perfect structural flow.

---

## 7. Frontend User Interfaces

### 1. Web Workspace (`web/src/pages/InvestigationWorkspace.tsx`):
- Rendered compact evidence card in the Overview section.
- `[DISPOSABLE]` badge rendered in calm amber (`#FF9F0A`)—never aggressive red—to reflect supporting context rather than confirmed malice.
- `[PRIVACY / FORWARDING SERVICE]` badge rendered in calm blue (`#5B8DEF`).
- Complete dataset attribution and explanatory text displayed for SOC analysts.

### 2. Mobile App (`mobile/src/screens/CaseDetailScreen.tsx`):
- Added dedicated `EMAIL PROVIDER INTELLIGENCE` card.
- Displays domain, provider, classification, and risk contribution.
- Embedded callout: *"Supporting forensic observation only. Technical domain classification does not prove malicious intent or establish actor identity."*

---

## 8. Frozen Machine Learning Models Integrity

All four ANVESH models remain frozen with byte-for-byte SHA-256 verification:

| Model | Model File | Expected SHA-256 Hash | Status |
|---|---|---|---|
| **Model 1: Phishing Baseline** | `phishing_email_model.pkl` | `f49c153fb5bb32ccb0b5904ee008f8bbec052f53b4ca6ccfaa5a6a93df0493d7` | **FROZEN & VERIFIED** |
| **Model 2: BEC Detector** | `bec_detector_model.pkl` | `afae6a334272907d7aa380216853d3543f5cd90fb6f8a5b7780eec7bcbb9aee8` | **FROZEN & VERIFIED** |
| **Model 3A: Identity Impersonation** | Deterministic Governed Engine | N/A (Rule Engine Code-Level Parity) | **FROZEN & VERIFIED** |
| **Model 3B: Lookalike Domain** | `lookalike_classifier_v1.pkl` | `31224d67d9d97660a5db20f5ac16cc1c24b8b22b86ec290240180f11c09d2559` | **FROZEN & VERIFIED** |

---

## 9. Test Results & Verification

### Test Suite Execution:
```powershell
& 'C:\Program Files\Python312\python.exe' -m pytest tests/test_disposable_email_intelligence.py -v
```
**Results**: **23 passed, 0 failed** in 2.24s.

### Full Platform Regression Execution:
```powershell
& 'C:\Program Files\Python312\python.exe' -m pytest tests/ -v
```
**Results**: **153 passed, 0 failed** in 60.42s (100% PASS across Phases 6-12.5).

### Frontend Builds:
- `cd SIH2026/web && npm run build` -> **0 errors (1841 modules transformed)**.
- `cd SIH2026/mobile && npx tsc --noEmit` -> **0 errors**.

---

## 10. Conclusion

Phase 12.5 has been completed with rigorous forensic fidelity. Disposable and temporary email detection now operates as an evidence-driven, explainable, bounded intelligence signal across ANVESH backend, report exports, web workspace, and mobile app, strictly observing all attribution boundaries and model freezes.
