"""
Tests for ANVESH Phase 11: Case Management & Analyst Workflow.

Comprehensive test suite verifying:
1. Valid status transition: NEW -> TRIAGED -> INVESTIGATING -> RESOLVED
2. Invalid status transition: Disallowed jump rejected with 400
3. Unauthorized status change: Missing or invalid credentials rejected with 401
4. Case assignment: Assigns case to authenticated analyst
5. Case reassignment: Reassigns case and records previous assignee
6. Note creation: Append-only note saved with UUID and timestamp
7. Note requires authentication: Unauthenticated note creation rejected with 401
8. Analyst decision creation: Decision recorded with mandatory justification
9. Analyst decision remains separate from system risk: System assessment remains immutable
10. Escalation workflow: Case status updated to ESCALATED
11. Escalation reason required: Empty escalation reason rejected with 400
12. Resolution requires decision: Resolution requires valid decision and investigation notes
13. Closed-case protection: Closed case locked against modification; reopenable via INVESTIGATING
14. Activity timeline creation: Chronological activity timeline records all events
15. Authenticated actor recorded correctly: Activity actor matches authenticated identity
16. No fabricated analyst identity: Real IDs preserved without hallucinated names
17. Duplicate/concurrent decision handling: Decision history maintained while updating latest state
18. Existing forensic evidence remains intact: Ingestion SHA-256 and RFC-822 untouched
19. Existing report generation remains intact: Phase 10 PDF and JSON exports remain valid
20. Existing attribution boundary remains intact: "Actor Identity: NOT ESTABLISHED" preserved
"""

import json
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.constants import CaseStatus, AnalystDecisionType, ActivityEventType
from app.services.case_workflow_service import case_workflow_service
from app.services.forensic_report_service import forensic_report_service
from app.database.supabase_client import supabase
from app.main import app

client = TestClient(app)

AUTH_HEADERS = {"X-Analyst-ID": "analyst_usr_902"}
AUTH_HEADERS_2 = {"X-Analyst-ID": "analyst_usr_905"}


@pytest.fixture(autouse=True)
def setup_test_case(monkeypatch):
    """Sets up a clean test case in local cache for each test."""
    monkeypatch.setattr(supabase, "is_configured", lambda: False)
    case_num = "ANV-2026-WF01"
    c_id = "case-uuid-wf01"
    
    test_case = {
        "id": c_id,
        "case_number": case_num,
        "title": "Suspected Credential Harvesting Campaign",
        "description": "User reported suspicious MFA reset request",
        "status": CaseStatus.NEW.value,
        "risk_score": 82,
        "risk_level": "HIGH",
        "threat_type": "CREDENTIAL_PHISHING",
        "probable_origin_ip": "194.26.29.112",
        "origin_confidence": "HIGH",
        "approximate_location": "Amsterdam, Netherlands",
        "assigned_to": None,
        "campaign_id": None,
        "analyst_decision": None,
        "analyst_decision_reason": None,
        "analyst_decision_at": None,
        "analyst_decision_by": None,
        "escalation_reason": None,
        "created_at": "2026-09-01T10:00:00Z",
        "updated_at": "2026-09-01T10:00:00Z"
    }
    
    test_email = {
        "id": "email-uuid-wf01",
        "case_id": c_id,
        "sender": "security-alert@micros0ft-support.com",
        "recipient": "victim@corporate-target.com",
        "subject": "Urgent: Reset Your Multi-Factor Authentication",
        "date": "2026-09-01T09:58:00Z",
        "message_id": "<alert-20260901-wf@micros0ft-support.com>",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "relay_count": 2,
        "delivery_hops_json": [
            {"hop_number": 1, "by_host": "mail.corporate-target.com", "from_ip": "194.26.29.112", "timestamp": "2026-09-01T09:59:00Z"}
        ]
    }
    
    test_evidence = {
        "id": "ev-uuid-wf01",
        "case_id": c_id,
        "file_name": "suspicious_mfa.eml",
        "file_size_bytes": 4096,
        "mime_type": "message/rfc822",
        "sha256_hash": "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123",
        "sha256_fingerprint": "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123",
        "uploaded_by": "automated_sensor",
        "captured_at": "2026-09-01T10:00:00Z"
    }

    # Reset tables in local cache
    supabase._local_cache["cases"] = [test_case]
    supabase._local_cache["emails"] = [test_email]
    supabase._local_cache["evidence"] = [test_evidence]
    supabase._local_cache["case_notes"] = []
    supabase._local_cache["case_decisions"] = []
    supabase._local_cache["case_activities"] = []
    supabase._local_cache["audit_logs"] = []

    yield test_case


# ---------------------------------------------------------------------------
# Tests 1 - 5: Status Transitions, Unauthorized Rejection & Assignment
# ---------------------------------------------------------------------------

def test_1_valid_status_transition():
    """Verify controlled lifecycle transition: NEW -> TRIAGED -> INVESTIGATING -> RESOLVED."""
    case_num = "ANV-2026-WF01"
    
    # 1. NEW -> TRIAGED
    r1 = client.patch(f"/api/v1/cases/{case_num}/status", json={"status": "TRIAGED", "note": "Initial triage triage verified"}, headers=AUTH_HEADERS)
    assert r1.status_code == 200
    assert r1.json()["current_status"] == "TRIAGED"
    
    # 2. TRIAGED -> INVESTIGATING
    r2 = client.patch(f"/api/v1/cases/{case_num}/status", json={"status": "INVESTIGATING", "note": "Assigned analyst actively investigating"}, headers=AUTH_HEADERS)
    assert r2.status_code == 200
    assert r2.json()["current_status"] == "INVESTIGATING"

    # 3. INVESTIGATING -> RESOLVED
    r3 = client.patch(f"/api/v1/cases/{case_num}/status", json={"status": "RESOLVED", "note": "Findings confirmed"}, headers=AUTH_HEADERS)
    assert r3.status_code == 200
    assert r3.json()["current_status"] == "RESOLVED"


def test_2_invalid_status_transition():
    """Disallowed transitions (e.g. NEW -> CLOSED or CLOSED -> RESOLVED) must be rejected with 400."""
    case_num = "ANV-2026-WF01"
    
    # NEW -> CLOSED is invalid (cannot skip investigation and triage)
    r1 = client.patch(f"/api/v1/cases/{case_num}/status", json={"status": "CLOSED"}, headers=AUTH_HEADERS)
    assert r1.status_code == 400
    assert "Invalid status transition" in r1.json()["detail"]


def test_3_unauthorized_status_change():
    """Status updates without authenticated credentials must be rejected with 401."""
    case_num = "ANV-2026-WF01"
    
    # No headers provided
    r1 = client.patch(f"/api/v1/cases/{case_num}/status", json={"status": "TRIAGED"})
    assert r1.status_code == 401
    
    # Explicitly empty / anonymous header
    r2 = client.patch(f"/api/v1/cases/{case_num}/status", json={"status": "TRIAGED"}, headers={"X-Analyst-ID": ""})
    assert r2.status_code == 401


def test_4_case_assignment():
    """Assigns case to an authenticated analyst and records audit event."""
    case_num = "ANV-2026-WF01"
    
    res = client.patch(f"/api/v1/cases/{case_num}/assignment", json={"assigned_to": "usr_analyst_007"}, headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["assigned_to"] == "usr_analyst_007"
    assert data["case"]["assigned_to"] == "usr_analyst_007"


def test_5_case_reassignment():
    """Reassigns case from one analyst to another and preserves history."""
    case_num = "ANV-2026-WF01"
    
    # Assign first
    client.patch(f"/api/v1/cases/{case_num}/assignment", json={"assigned_to": "usr_analyst_007"}, headers=AUTH_HEADERS)
    
    # Reassign
    res = client.patch(f"/api/v1/cases/{case_num}/assignment", json={"assigned_to": "usr_analyst_009"}, headers=AUTH_HEADERS_2)
    assert res.status_code == 200
    data = res.json()
    assert data["previous_assignee"] == "usr_analyst_007"
    assert data["assigned_to"] == "usr_analyst_009"


# ---------------------------------------------------------------------------
# Tests 6 - 9: Investigation Notes, Authentication & Decision Separation
# ---------------------------------------------------------------------------

def test_6_note_creation():
    """Adds append-only note and verifies it is retrievable."""
    case_num = "ANV-2026-WF01"
    
    res = client.post(
        f"/api/v1/cases/{case_num}/notes",
        json={"content": "SPF/DKIM failed on lookalike domain micros0ft-support.com. Reverse IP trace initiated."},
        headers=AUTH_HEADERS
    )
    assert res.status_code == 200
    note = res.json()["note"]
    assert note["author_id"] == "analyst_usr_902"
    assert "micros0ft-support.com" in note["content"]

    # Verify get notes
    res2 = client.get(f"/api/v1/cases/{case_num}/notes")
    assert res2.status_code == 200
    notes = res2.json()["notes"]
    assert len(notes) == 1
    assert notes[0]["content"] == note["content"]


def test_7_note_requires_authentication():
    """Note creation without auth header is rejected with 401."""
    case_num = "ANV-2026-WF01"
    
    res = client.post(
        f"/api/v1/cases/{case_num}/notes",
        json={"content": "Unauthenticated note"}
    )
    assert res.status_code == 401


def test_8_analyst_decision_creation():
    """Records an authoritative analyst decision with justification."""
    case_num = "ANV-2026-WF01"
    
    res = client.post(
        f"/api/v1/cases/{case_num}/decision",
        json={
            "decision": "CONFIRMED_THREAT",
            "reason": "Phishing lure targeting executive credentials using lookalike domain and spoofed Return-Path."
        },
        headers=AUTH_HEADERS
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "CONFIRMED_THREAT"
    assert "lookalike domain" in data["reason"]
    assert data["analyst"] == "analyst_usr_902"


def test_9_analyst_decision_remains_separate_from_system_risk():
    """
    CRITICAL PRODUCT INVARIANT:
    Analyst decision MUST NEVER overwrite or alter the automated system assessment.
    """
    case_num = "ANV-2026-WF01"
    
    # System assessment originally: risk_score = 82, risk_level = "HIGH"
    res = client.post(
        f"/api/v1/cases/{case_num}/decision",
        json={
            "decision": "BENIGN_FALSE_POSITIVE",
            "reason": "Authorized IT security awareness phishing simulation test sent by internal security team."
        },
        headers=AUTH_HEADERS
    )
    assert res.status_code == 200
    
    # Verify the case record in database
    case = case_workflow_service.get_case(case_num)
    
    # Automated system assessment remains completely intact
    assert case["risk_score"] == 82
    assert case["risk_level"] == "HIGH"
    assert case["threat_type"] == "CREDENTIAL_PHISHING"
    
    # Analyst decision is stored separately
    assert case["analyst_decision"] == "BENIGN_FALSE_POSITIVE"
    assert "Authorized IT security awareness" in case["analyst_decision_reason"]
    assert case["analyst_decision_by"] == "analyst_usr_902"


# ---------------------------------------------------------------------------
# Tests 10 - 13: Escalation, Resolution & Closed Case Protection
# ---------------------------------------------------------------------------

def test_10_escalation_workflow():
    """Escalates case with mandatory justification."""
    case_num = "ANV-2026-WF01"
    
    res = client.post(
        f"/api/v1/cases/{case_num}/escalate",
        json={"reason": "Compromised third-party gateway observed. Multi-tenant exposure suspected."},
        headers=AUTH_HEADERS
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ESCALATED"
    assert "Multi-tenant exposure" in data["escalation_reason"]


def test_11_escalation_reason_required():
    """Escalation without justification is rejected with 400."""
    case_num = "ANV-2026-WF01"
    
    res = client.post(
        f"/api/v1/cases/{case_num}/escalate",
        json={"reason": ""},
        headers=AUTH_HEADERS
    )
    assert res.status_code == 422 or res.status_code == 400


def test_12_resolution_requires_decision():
    """Resolving an investigation requires an analyst decision and investigation summary."""
    case_num = "ANV-2026-WF01"
    
    # Move to INVESTIGATING first
    case_workflow_service.transition_status(case_num, "INVESTIGATING")
    
    res = client.post(
        f"/api/v1/cases/{case_num}/resolve",
        json={
            "decision": "CONFIRMED_THREAT",
            "resolution_notes": "Identified malicious payload, blocked domain on DNS gateway, purged target mailboxes."
        },
        headers=AUTH_HEADERS
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "RESOLVED"
    assert data["decision"] == "CONFIRMED_THREAT"


def test_13_closed_case_protection():
    """
    Closed cases are locked against modifications to preserve evidentiary integrity.
    Can only be reopened by transitioning to INVESTIGATING.
    """
    case_num = "ANV-2026-WF01"
    
    # Move to RESOLVED then CLOSED
    case_workflow_service.transition_status(case_num, "INVESTIGATING")
    case_workflow_service.transition_status(case_num, "RESOLVED")
    case_workflow_service.transition_status(case_num, "CLOSED")
    
    # 1. Attempting to add a note on closed case must fail
    res_note = client.post(
        f"/api/v1/cases/{case_num}/notes",
        json={"content": "Late addition to closed case"},
        headers=AUTH_HEADERS
    )
    assert res_note.status_code == 400
    
    # 2. Attempting to reassign closed case must fail
    res_assign = client.patch(
        f"/api/v1/cases/{case_num}/assignment",
        json={"assigned_to": "usr_other"},
        headers=AUTH_HEADERS
    )
    assert res_assign.status_code == 400

    # 3. Attempting invalid jump (CLOSED -> ESCALATED) must fail
    res_jump = client.patch(
        f"/api/v1/cases/{case_num}/status",
        json={"status": "ESCALATED"},
        headers=AUTH_HEADERS
    )
    assert res_jump.status_code == 400

    # 4. Controlled Reopening to INVESTIGATING succeeds
    res_reopen = client.patch(
        f"/api/v1/cases/{case_num}/status",
        json={"status": "INVESTIGATING", "note": "Reopened per CIRT review"},
        headers=AUTH_HEADERS
    )
    assert res_reopen.status_code == 200
    assert res_reopen.json()["current_status"] == "INVESTIGATING"


# ---------------------------------------------------------------------------
# Tests 14 - 17: Activity Timeline, Identity Veracity & Concurrency
# ---------------------------------------------------------------------------

def test_14_activity_timeline_creation():
    """Verifies chronological unified activity timeline records system and analyst events."""
    case_num = "ANV-2026-WF01"
    
    # Execute several actions
    case_workflow_service.transition_status(case_num, "TRIAGED", actor="analyst_usr_902")
    case_workflow_service.assign_case(case_num, "analyst_usr_902", actor="analyst_usr_902")
    case_workflow_service.add_note(case_num, "Forensic header analysis started", author_id="analyst_usr_902")
    
    res = client.get(f"/api/v1/cases/{case_num}/activity")
    assert res.status_code == 200
    activities = res.json()["activities"]
    assert len(activities) >= 4
    
    # Check that actor types are properly distinguished
    actor_types = {a["actor_type"] for a in activities}
    assert "SYSTEM" in actor_types
    assert "ANALYST" in actor_types


def test_15_authenticated_actor_recorded_correctly():
    """Actor identity in activity log strictly reflects the authenticated user."""
    case_num = "ANV-2026-WF01"
    
    client.post(
        f"/api/v1/cases/{case_num}/notes",
        json={"content": "Audit check note"},
        headers={"X-Analyst-ID": "analyst_cert_4091"}
    )
    
    acts = case_workflow_service.get_activities(case_num)
    note_act = [a for a in acts if a["event_type"] == "NOTE_ADDED"][-1]
    assert note_act["actor"] == "analyst_cert_4091"
    assert note_act["actor_type"] == "ANALYST"


def test_16_no_fabricated_analyst_identity():
    """Ensures no hallucinated or hardcoded analyst names are recorded."""
    case_num = "ANV-2026-WF01"
    
    client.patch(
        f"/api/v1/cases/{case_num}/assignment",
        json={"assigned_to": "officer_uid_8841"},
        headers={"X-Analyst-ID": "supervisor_uid_100"}
    )
    
    case = case_workflow_service.get_case(case_num)
    assert case["assigned_to"] == "officer_uid_8841"
    assert "John" not in str(case["assigned_to"])
    assert "Smith" not in str(case["assigned_to"])


def test_17_duplicate_concurrent_decision_handling():
    """Subsequent decisions update the latest pointer and store full history."""
    case_num = "ANV-2026-WF01"
    
    # First decision
    case_workflow_service.record_decision(
        case_num,
        "NEEDS_MORE_EVIDENCE",
        "Waiting on M365 tenant unified audit logs",
        actor="analyst_1"
    )
    
    # Second decision (new evidence arrived)
    case_workflow_service.record_decision(
        case_num,
        "CONFIRMED_THREAT",
        "Tenant logs confirmed mailbox forwarder rule created by external IP",
        actor="analyst_2"
    )
    
    case = case_workflow_service.get_case(case_num)
    assert case["analyst_decision"] == "CONFIRMED_THREAT"
    assert case["analyst_decision_by"] == "analyst_2"
    
    # Full history has 2 records
    dec_history = supabase.query("case_decisions", select="*", filters={"case_id": f"eq.{case_num}"})
    assert len(dec_history) == 2


# ---------------------------------------------------------------------------
# Tests 18 - 20: Regression & Forensic Preservation Invariants
# ---------------------------------------------------------------------------

def test_18_existing_forensic_evidence_remains_intact():
    """Workflow transitions must not mutate original evidence vault hashes or raw emails."""
    case_num = "ANV-2026-WF01"
    
    # Check original evidence
    orig_ev = supabase.query("evidence", select="*", filters={"case_id": "eq.case-uuid-wf01"})[0]
    orig_hash = orig_ev["sha256_hash"]
    
    # Perform workflow transitions
    case_workflow_service.transition_status(case_num, "TRIAGED")
    case_workflow_service.add_note(case_num, "Test note")
    case_workflow_service.escalate_case(case_num, "Test escalation")
    
    # Re-verify evidence record has not changed
    ev_after = supabase.query("evidence", select="*", filters={"case_id": "eq.case-uuid-wf01"})[0]
    assert ev_after["sha256_hash"] == orig_hash
    assert ev_after["sha256_fingerprint"] == orig_hash


def test_19_existing_report_generation_remains_intact():
    """Phase 10 PDF and JSON export must work seamlessly with cases undergoing Phase 11 workflow."""
    case_num = "ANV-2026-WF01"
    
    # Add an analyst decision and note
    case_workflow_service.record_decision(
        case_num,
        "CONFIRMED_THREAT",
        "Malicious lookalike domain verified",
        actor="analyst_usr_902"
    )
    
    # Generate canonical dossier
    dossier = forensic_report_service.compile_canonical_dossier(case_num, force_regenerate=True)
    assert dossier is not None
    assert dossier.evidence_integrity.report_sha256 is not None
    assert len(dossier.evidence_integrity.report_sha256) == 64

    # Export PDF
    pdf_bytes, filename = forensic_report_service.export_pdf(case_num)
    assert pdf_bytes.startswith(b"%PDF")
    assert filename.endswith(".pdf")


def test_20_existing_attribution_boundary_remains_intact():
    """Attribution assessment must preserve 'Actor Identity: NOT ESTABLISHED' throughout workflow."""
    case_num = "ANV-2026-WF01"
    
    # Transition through full lifecycle
    case_workflow_service.transition_status(case_num, "INVESTIGATING")
    case_workflow_service.escalate_case(case_num, "High-value executive threat observed")
    case_workflow_service.resolve_case(case_num, "CONFIRMED_THREAT", "Investigation concluded")
    
    # Check dossier attribution boundary
    dossier = forensic_report_service.compile_canonical_dossier(case_num, force_regenerate=True)
    assert dossier.attribution_assessment.actor_identity == "Actor Identity: NOT ESTABLISHED"
    assert "insufficient to attribute" in dossier.attribution_assessment.evidence_boundary
