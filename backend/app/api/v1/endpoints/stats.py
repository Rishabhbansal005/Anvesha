"""
ANVESH Dashboard telemetry endpoint.
Queries real Supabase records. Returns exact zeros and empty collections when database is empty.
"""
from fastapi import APIRouter
from app.database.supabase_client import supabase

router = APIRouter()


@router.get("/overview", summary="Analyst Attention Overview")
def get_dashboard_overview():
    """
    Answers: What requires my attention?
    Driven dynamically by real Supabase database records. Zero hardcoded mock numbers.
    """
    # Query actual records from Supabase
    cases = supabase.query("cases", select="id,case_number,title,risk_score,risk_level,status,created_at", order="risk_score.desc", limit=10)
    alerts = supabase.query("alerts", select="id,title,risk_score,risk_level,is_reviewed", order="created_at.desc", limit=10)
    campaigns = supabase.query("campaigns", select="id,name,severity,is_active", filters={"is_active": "eq.true"})
    
    total_investigations = len(cases)
    unreviewed_alerts = len([a for a in alerts if not a.get("is_reviewed", False)])
    critical_threats = len([c for c in cases if c.get("risk_score", 0) >= 85])
    active_campaigns_count = len(campaigns)

    # Filter items that actually require analyst attention (Critical/High unreviewed)
    attention_items = []
    for c in cases:
        if c.get("risk_score", 0) >= 70 and c.get("status") in ("NEW", "UNDER_REVIEW", "ESCALATED"):
            attention_items.append({
                "id": str(c.get("id")),
                "case_number": c.get("case_number", "CASE-UNKNOWN"),
                "title": c.get("title", "Untitled Case"),
                "risk_score": c.get("risk_score", 0),
                "risk_level": c.get("risk_level", "HIGH"),
                "status": c.get("status", "NEW"),
                "created_at": c.get("created_at", "")
            })

    # Recent real activity
    recent_activity = []
    for c in cases[:5]:
        recent_activity.append({
            "id": f"ACT-{c.get('case_number', 'CASE')}",
            "type": "INVESTIGATION_LOG",
            "description": f"Investigation {c.get('case_number')} recorded with risk {c.get('risk_score')}/100",
            "timestamp": c.get("created_at", "Recently")
        })

    return {
        "total_investigations": total_investigations,
        "critical_threats": critical_threats,
        "unreviewed_alerts_count": unreviewed_alerts,
        "active_campaigns_count": active_campaigns_count,
        "urgent_actions_required": attention_items,
        "recent_activity": recent_activity,
        "has_records": total_investigations > 0 or unreviewed_alerts > 0,
        "is_simulated_data": False,
        "system_status": "OPERATIONAL"
    }
