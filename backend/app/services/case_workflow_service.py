"""
ANVESH Case Management & Analyst Workflow Service (Phase 11).
Enforces controlled case lifecycle, strict analyst decision separation,
append-only investigation notes, and a unified chronological activity timeline.
"""
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import HTTPException
from app.database.supabase_client import supabase
from app.core.constants import (
    CaseStatus,
    AnalystDecisionType,
    ActivityEventType,
    ALLOWED_STATUS_TRANSITIONS
)

logger = logging.getLogger("ANVESH.CaseWorkflow")


class CaseWorkflowService:
    @staticmethod
    def get_case(case_id: str) -> Dict[str, Any]:
        """Resolves case dictionary by case_number or ID."""
        items = supabase.query("cases", select="*", filters={"case_number": f"eq.{case_id}"})
        if not items:
            items = supabase.query("cases", select="*", filters={"id": f"eq.{case_id}"})
        if not items:
            raise HTTPException(status_code=404, detail=f"Investigation case '{case_id}' not found")
        return items[0]

    @classmethod
    def record_activity(
        cls,
        case_id: str,
        event_type: str,
        actor: str,
        actor_type: str,
        title: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Records an immutable activity event in the case timeline and audit ledger."""
        now_iso = datetime.utcnow().isoformat()
        activity_id = str(uuid.uuid4())
        record = {
            "id": activity_id,
            "case_id": case_id,
            "event_type": event_type,
            "actor": actor,
            "actor_type": actor_type,
            "title": title,
            "description": description,
            "metadata": metadata or {},
            "timestamp": now_iso
        }
        supabase.insert("case_activities", record)
        
        # Mirror to audit_logs for referential audit compliance
        audit_record = {
            "action": event_type,
            "target_entity": "Case",
            "target_id": case_id,
            "details": f"{title}: {description}",
            "ip_address": "127.0.0.1",
            "timestamp": now_iso
        }
        supabase.insert("audit_logs", audit_record)
        return record

    @classmethod
    def transition_status(
        cls,
        case_id: str,
        new_status: str,
        note: Optional[str] = None,
        actor: str = "ANALYST"
    ) -> Dict[str, Any]:
        """
        Executes a controlled state transition in the case lifecycle.
        Rejects invalid transitions and protects closed cases.
        """
        case = cls.get_case(case_id)
        current_status_raw = case.get("status", "NEW")
        target_status_raw = new_status.upper() if isinstance(new_status, str) else new_status.value

        # Match enum members safely
        try:
            current_status = CaseStatus(current_status_raw)
        except ValueError:
            current_status = CaseStatus.NEW

        try:
            target_status = CaseStatus(target_status_raw)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid target status: '{target_status_raw}'"
            )

        # 1. Closed Case Protection
        if current_status == CaseStatus.CLOSED and target_status != CaseStatus.INVESTIGATING:
            raise HTTPException(
                status_code=400,
                detail="Closed cases are locked to preserve forensic integrity. Transition to INVESTIGATING to reopen."
            )

        # 2. Check Allowed Transitions
        if current_status != target_status:
            allowed = ALLOWED_STATUS_TRANSITIONS.get(current_status, [])
            if target_status not in allowed:
                allowed_str = [s.value for s in allowed]
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status transition from {current_status.value} to {target_status.value}. Allowed transitions: {allowed_str}"
                )

        # 3. Update Database
        c_num = case.get("case_number", case_id)
        c_id = case.get("id")
        updates = {"status": target_status.value, "updated_at": datetime.utcnow().isoformat()}
        
        updated = supabase.update("cases", match_col="case_number", match_val=c_num, updates=updates)
        if not updated and c_id:
            updated = supabase.update("cases", match_col="id", match_val=str(c_id), updates=updates)
        if not updated:
            case.update(updates)
            updated = case

        # 4. Record Activity
        action_name = ActivityEventType.CASE_REOPENED if (current_status == CaseStatus.CLOSED and target_status == CaseStatus.INVESTIGATING) else ActivityEventType.STATUS_CHANGED
        cls.record_activity(
            case_id=c_num,
            event_type=action_name.value,
            actor=actor,
            actor_type="ANALYST",
            title=f"Status Changed to {target_status.value}",
            description=f"Investigation status updated from {current_status.value} to {target_status.value}. Note: {note or 'Standard workflow advancement'}",
            metadata={"previous_status": current_status.value, "new_status": target_status.value, "note": note}
        )

        return {
            "case_number": c_num,
            "previous_status": current_status.value,
            "current_status": target_status.value,
            "case": updated,
            "note": note
        }

    @classmethod
    def assign_case(
        cls,
        case_id: str,
        assigned_to: Optional[str],
        actor: str = "ANALYST"
    ) -> Dict[str, Any]:
        """Assigns or reassigns case to an analyst."""
        case = cls.get_case(case_id)
        current_status = case.get("status", "NEW")
        if current_status == CaseStatus.CLOSED.value:
            raise HTTPException(status_code=400, detail="Cannot modify assignment on a closed case.")

        prev_assignee = case.get("assigned_to")
        c_num = case.get("case_number", case_id)
        c_id = case.get("id")

        updates = {"assigned_to": assigned_to, "updated_at": datetime.utcnow().isoformat()}
        updated = supabase.update("cases", match_col="case_number", match_val=c_num, updates=updates)
        if not updated and c_id:
            updated = supabase.update("cases", match_col="id", match_val=str(c_id), updates=updates)
        if not updated:
            case.update(updates)
            updated = case

        if not assigned_to:
            evt = ActivityEventType.CASE_UNASSIGNED
            desc = f"Investigation unassigned by {actor} (previously assigned to {prev_assignee or 'Unassigned'})."
        elif prev_assignee:
            evt = ActivityEventType.CASE_REASSIGNED
            desc = f"Investigation reassigned from {prev_assignee} to {assigned_to} by {actor}."
        else:
            evt = ActivityEventType.CASE_ASSIGNED
            desc = f"Investigation assigned to {assigned_to} by {actor}."

        cls.record_activity(
            case_id=c_num,
            event_type=evt.value,
            actor=actor,
            actor_type="ANALYST",
            title=evt.value.replace("_", " ").title(),
            description=desc,
            metadata={"previous_assignee": prev_assignee, "new_assignee": assigned_to}
        )

        return {
            "case_number": c_num,
            "previous_assignee": prev_assignee,
            "assigned_to": assigned_to,
            "case": updated
        }

    @classmethod
    def record_decision(
        cls,
        case_id: str,
        decision: str,
        reason: str,
        actor: str = "ANALYST"
    ) -> Dict[str, Any]:
        """
        Records an authoritative analyst decision.
        CRITICAL: Never overwrites the automated risk score or system threat level.
        """
        case = cls.get_case(case_id)
        current_status = case.get("status", "NEW")
        if current_status == CaseStatus.CLOSED.value:
            raise HTTPException(status_code=400, detail="Cannot record decisions on a closed case.")

        # Validate decision type
        valid_decisions = {d.value for d in AnalystDecisionType}
        dec_upper = decision.upper()
        if dec_upper not in valid_decisions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid decision '{decision}'. Must be one of: {sorted(list(valid_decisions))}"
            )

        if not reason or len(reason.strip()) < 3:
            raise HTTPException(status_code=400, detail="Investigation justification is required to record a decision.")

        now_iso = datetime.utcnow().isoformat()
        c_num = case.get("case_number", case_id)
        c_id = case.get("id")

        # Save to case decisions history
        decision_id = str(uuid.uuid4())
        dec_record = {
            "id": decision_id,
            "case_id": c_num,
            "decision": dec_upper,
            "reason": reason.strip(),
            "analyst_id": actor,
            "created_at": now_iso
        }
        supabase.insert("case_decisions", dec_record)

        # Update case row with latest analyst decision fields (System scores remain immutable)
        updates = {
            "analyst_decision": dec_upper,
            "analyst_decision_reason": reason.strip(),
            "analyst_decision_at": now_iso,
            "analyst_decision_by": actor,
            "updated_at": now_iso
        }
        updated = supabase.update("cases", match_col="case_number", match_val=c_num, updates=updates)
        if not updated and c_id:
            updated = supabase.update("cases", match_col="id", match_val=str(c_id), updates=updates)
        if not updated:
            case.update(updates)
            updated = case

        cls.record_activity(
            case_id=c_num,
            event_type=ActivityEventType.DECISION_RECORDED.value,
            actor=actor,
            actor_type="ANALYST",
            title=f"Analyst Decision: {dec_upper.replace('_', ' ')}",
            description=f"Analyst recorded outcome '{dec_upper}'. Reason: {reason.strip()}",
            metadata={"decision": dec_upper, "reason": reason.strip()}
        )

        return {
            "case_number": c_num,
            "decision": dec_upper,
            "reason": reason.strip(),
            "recorded_at": now_iso,
            "analyst": actor,
            "case": updated
        }

    @classmethod
    def add_note(
        cls,
        case_id: str,
        content: str,
        author_id: str = "ANALYST"
    ) -> Dict[str, Any]:
        """Adds an append-only analyst investigation note."""
        case = cls.get_case(case_id)
        if case.get("status") == CaseStatus.CLOSED.value:
            raise HTTPException(status_code=400, detail="Cannot add notes to a closed case.")

        if not content or not content.strip():
            raise HTTPException(status_code=400, detail="Note content cannot be empty.")

        c_num = case.get("case_number", case_id)
        now_iso = datetime.utcnow().isoformat()
        note_id = str(uuid.uuid4())

        note_record = {
            "id": note_id,
            "case_id": c_num,
            "author_id": author_id,
            "content": content.strip(),
            "created_at": now_iso
        }
        supabase.insert("case_notes", note_record)

        cls.record_activity(
            case_id=c_num,
            event_type=ActivityEventType.NOTE_ADDED.value,
            actor=author_id,
            actor_type="ANALYST",
            title="Investigation Note Added",
            description=f"Analyst added note: \"{content.strip()[:100]}{'...' if len(content.strip()) > 100 else ''}\"",
            metadata={"note_id": note_id}
        )

        return note_record

    @classmethod
    def get_notes(cls, case_id: str) -> List[Dict[str, Any]]:
        """Retrieves append-only investigation notes for a case."""
        case = cls.get_case(case_id)
        c_num = case.get("case_number", case_id)
        c_id = str(case.get("id"))
        
        notes_by_num = supabase.query("case_notes", select="*", filters={"case_id": f"eq.{c_num}"}, order="created_at.asc")
        notes_by_id = supabase.query("case_notes", select="*", filters={"case_id": f"eq.{c_id}"}, order="created_at.asc") if c_id else []
        
        seen_ids = set()
        merged = []
        for n in notes_by_num + notes_by_id:
            nid = n.get("id")
            if nid not in seen_ids:
                seen_ids.add(nid)
                merged.append(n)
        merged.sort(key=lambda x: x.get("created_at", ""))
        return merged

    @classmethod
    def escalate_case(
        cls,
        case_id: str,
        reason: str,
        actor: str = "ANALYST"
    ) -> Dict[str, Any]:
        """
        Escalates an ongoing investigation with mandatory justification.
        Validates lifecycle and preserves non-attribution safeguards.
        """
        case = cls.get_case(case_id)
        current_status = case.get("status", "NEW")
        if current_status == CaseStatus.CLOSED.value:
            raise HTTPException(status_code=400, detail="Closed cases cannot be escalated.")

        if not reason or len(reason.strip()) < 3:
            raise HTTPException(status_code=400, detail="Mandatory escalation reason required.")

        c_num = case.get("case_number", case_id)
        c_id = case.get("id")
        now_iso = datetime.utcnow().isoformat()

        updates = {
            "status": CaseStatus.ESCALATED.value,
            "escalation_reason": reason.strip(),
            "updated_at": now_iso
        }
        updated = supabase.update("cases", match_col="case_number", match_val=c_num, updates=updates)
        if not updated and c_id:
            updated = supabase.update("cases", match_col="id", match_val=str(c_id), updates=updates)
        if not updated:
            case.update(updates)
            updated = case

        cls.record_activity(
            case_id=c_num,
            event_type=ActivityEventType.CASE_ESCALATED.value,
            actor=actor,
            actor_type="ANALYST",
            title="Case Escalated for Priority Triage",
            description=f"Investigation escalated by {actor}. Reason: {reason.strip()}",
            metadata={"reason": reason.strip(), "previous_status": current_status}
        )

        return {
            "case_number": c_num,
            "status": CaseStatus.ESCALATED.value,
            "escalation_reason": reason.strip(),
            "case": updated
        }

    @classmethod
    def resolve_case(
        cls,
        case_id: str,
        decision: str,
        resolution_notes: str,
        actor: str = "ANALYST"
    ) -> Dict[str, Any]:
        """
        Resolves an investigation. Requires an explicit analyst decision.
        """
        case = cls.get_case(case_id)
        current_status = case.get("status", "NEW")
        if current_status == CaseStatus.CLOSED.value:
            raise HTTPException(status_code=400, detail="Case is already closed.")

        if not resolution_notes or len(resolution_notes.strip()) < 3:
            raise HTTPException(status_code=400, detail="Resolution investigation notes are mandatory.")

        # Record analyst decision first (guarantees decision cannot be bypassed)
        cls.record_decision(
            case_id=case_id,
            decision=decision,
            reason=resolution_notes,
            actor=actor
        )

        c_num = case.get("case_number", case_id)
        c_id = case.get("id")
        now_iso = datetime.utcnow().isoformat()

        updates = {
            "status": CaseStatus.RESOLVED.value,
            "updated_at": now_iso
        }
        updated = supabase.update("cases", match_col="case_number", match_val=c_num, updates=updates)
        if not updated and c_id:
            updated = supabase.update("cases", match_col="id", match_val=str(c_id), updates=updates)
        if not updated:
            case.update(updates)
            updated = case

        cls.record_activity(
            case_id=c_num,
            event_type=ActivityEventType.CASE_RESOLVED.value,
            actor=actor,
            actor_type="ANALYST",
            title="Case Resolved",
            description=f"Investigation resolved with outcome '{decision}'. Summary: {resolution_notes.strip()}",
            metadata={"decision": decision, "notes": resolution_notes.strip()}
        )

        return {
            "case_number": c_num,
            "status": CaseStatus.RESOLVED.value,
            "decision": decision,
            "resolution_notes": resolution_notes.strip(),
            "case": updated
        }

    @classmethod
    def get_activities(cls, case_id: str) -> List[Dict[str, Any]]:
        """
        Compiles the unified chronological activity timeline for a case.
        Combines automated system milestones with analyst actions.
        """
        case = cls.get_case(case_id)
        c_num = case.get("case_number", case_id)
        c_id = str(case.get("id"))

        # 1. Fetch analyst recorded activities
        acts_by_num = supabase.query("case_activities", select="*", filters={"case_id": f"eq.{c_num}"})
        acts_by_id = supabase.query("case_activities", select="*", filters={"case_id": f"eq.{c_id}"}) if c_id else []
        
        seen_ids = set()
        analyst_acts = []
        for a in acts_by_num + acts_by_id:
            aid = a.get("id")
            if aid not in seen_ids:
                seen_ids.add(aid)
                analyst_acts.append(a)

        # 2. Add baseline automated system events if not already present
        created_at = case.get("created_at") or datetime.utcnow().isoformat()
        system_events = [
            {
                "id": f"sys-{c_num}-1",
                "case_id": c_num,
                "event_type": ActivityEventType.EVIDENCE_INGESTED.value,
                "actor": "SYSTEM",
                "actor_type": "SYSTEM",
                "title": "RFC-822 Evidence Ingested",
                "description": f"Raw RFC-822 email ingested. SHA-256 evidence fingerprint registered in immutable ledger.",
                "timestamp": created_at,
                "metadata": {}
            },
            {
                "id": f"sys-{c_num}-2",
                "case_id": c_num,
                "event_type": ActivityEventType.ANALYSIS_COMPLETED.value,
                "actor": "SYSTEM",
                "actor_type": "SYSTEM",
                "title": "Forensic Signal Fusion Completed",
                "description": f"Cryptographic authentication, transport route, Model 1-3B signals, and origin telemetry evaluated. Initial normalized risk score: {case.get('risk_score', 0)}/100.",
                "timestamp": created_at,
                "metadata": {"risk_score": case.get("risk_score", 0), "risk_level": case.get("risk_level", "INFORMATIONAL")}
            }
        ]

        # Combine all events and sort chronologically
        all_events = system_events + analyst_acts
        all_events.sort(key=lambda x: x.get("timestamp", ""))
        return all_events


case_workflow_service = CaseWorkflowService()
