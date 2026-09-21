"""
ANVESH Alert Triage endpoints.
Queries and updates real Supabase alert records. Zero fake alert arrays.
"""
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from app.database.supabase_client import supabase
from app.schemas.alert import AlertTriageAction

router = APIRouter()


@router.get("", summary="List Real Threat Alerts")
def list_alerts(
    unreviewed_only: bool = Query(False, description="Filter only unreviewed alerts")
):
    filters = {}
    if unreviewed_only:
        filters["is_reviewed"] = "eq.false"

    items = supabase.query("alerts", select="*", filters=filters, order="risk_score.desc")

    return {
        "items": items,
        "total": len(items),
        "is_simulated_data": False
    }


@router.post("/{alert_id}/triage", summary="Triage Alert Action")
def triage_alert(alert_id: str, action: AlertTriageAction):
    updates = {}
    if action.action == "REVIEW":
        updates["is_reviewed"] = True
    elif action.action == "ESCALATE":
        updates["is_escalated"] = True
        updates["is_reviewed"] = True

    updated = supabase.update("alerts", match_col="id", match_val=alert_id, updates=updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found or update failed")

    return {
        "message": f"Action '{action.action}' applied to Alert {alert_id}",
        "alert": updated,
        "note": action.note
    }
