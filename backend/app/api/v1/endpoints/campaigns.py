"""
ANVESH Campaign Intelligence Endpoints.
Deterministic Evidence Correlation, Campaign Dossiers, and Relationship Graph.
Strict Zero-Fabrication and Non-Attribution Enforcement.
"""
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from app.database.supabase_client import supabase
from app.services.campaign_service import campaign_service

router = APIRouter()


class CorrelationRequest(BaseModel):
    case_id_a: str = Field(..., description="First case number or UUID to evaluate")
    case_id_b: str = Field(..., description="Second case number or UUID to evaluate")


def _resolve_campaign(campaign_id: str) -> Dict[str, Any]:
    """Helper to query campaign by UUID or human-readable campaign_id."""
    camps = supabase.query("campaigns", select="*", filters={"id": f"eq.{campaign_id}"})
    if not camps:
        camps = supabase.query("campaigns", select="*", filters={"campaign_id": f"eq.{campaign_id}"})
    if not camps:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return camps[0]


@router.get("", summary="List Active Campaigns from Database")
def list_campaigns(
    status: Optional[str] = Query(None, description="Filter by status: NEW, ACTIVE, REVIEW, CLOSED"),
    confidence: Optional[str] = Query(None, description="Filter by confidence: HIGH, MEDIUM, LOW"),
    q: Optional[str] = Query(None, description="Search term across campaign name, ID, or description")
):
    """
    Returns list of discovered potential threat campaigns.
    """
    filters = {}
    if status and status.upper() != "ALL":
        filters["status"] = f"eq.{status.upper()}"
    if confidence and confidence.upper() != "ALL":
        filters["confidence"] = f"eq.{confidence.upper()}"

    items = supabase.query("campaigns", select="*", filters=filters, order="last_observed_at.desc")

    if q and q.strip():
        term = q.strip().lower()
        items = [
            c for c in items
            if term in str(c.get("name", "")).lower()
            or term in str(c.get("campaign_id", "")).lower()
            or term in str(c.get("description", "")).lower()
            or term in str(c.get("explanation", "")).lower()
        ]

    return {
        "items": items,
        "total": len(items),
        "is_simulated_data": False
    }


@router.get("/{campaign_id}", summary="Get Detailed Campaign Dossier")
def get_campaign_details(campaign_id: str):
    """
    Returns comprehensive campaign dossier:
    - Campaign metadata
    - Machine-generated deterministic explanation
    - Related cases
    - Summary of observed infrastructure
    - Chronological timeline
    """
    camp = _resolve_campaign(campaign_id)
    c_uuid = camp.get("id")

    # Fetch related cases
    cases = supabase.query("cases", select="*", filters={"campaign_id": f"eq.{c_uuid}"})

    # Fetch timeline
    timeline = campaign_service.get_campaign_timeline(c_uuid)

    # Build observables summary
    relationships = campaign_service.get_campaign_relationships(c_uuid)

    return {
        "campaign": camp,
        "cases": cases,
        "case_count": len(cases),
        "timeline": timeline,
        "observables_summary": relationships.get("summary", {}),
        "disclaimer": "Campaign grouping indicates observed infrastructure and behavioral correlation. It does not establish common physical actor identity.",
        "is_simulated_data": False
    }


@router.get("/{campaign_id}/relationships", summary="Get Campaign Relationship Graph")
def get_campaign_relationships(campaign_id: str):
    """
    Returns node-and-edge relationship structure representing campaign evidence:
    Nodes: CAMPAIGN, CASE, EMAIL, DOMAIN, IP, URL, REPLY_TO, SENDER
    Edges: INCLUDES_CASE, INGESTED_EMAIL, OBSERVED_DOMAIN, OBSERVED_IP, OBSERVED_URL, SPECIFIES_REPLY_TO
    """
    camp = _resolve_campaign(campaign_id)
    c_uuid = camp.get("id")
    graph = campaign_service.get_campaign_relationships(c_uuid)
    return {
        "campaign_id": camp.get("campaign_id") or c_uuid,
        "campaign_name": camp.get("name"),
        "confidence": camp.get("confidence"),
        "nodes": graph.get("nodes", []),
        "edges": graph.get("edges", []),
        "summary": graph.get("summary", {}),
        "is_simulated_data": False
    }


@router.get("/{campaign_id}/timeline", summary="Get Chronological Campaign Timeline")
def get_campaign_timeline(campaign_id: str):
    """
    Returns chronological timeline events derived from actual evidence timestamps.
    """
    camp = _resolve_campaign(campaign_id)
    c_uuid = camp.get("id")
    timeline = campaign_service.get_campaign_timeline(c_uuid)
    return {
        "campaign_id": camp.get("campaign_id") or c_uuid,
        "timeline": timeline,
        "total_events": len(timeline),
        "is_simulated_data": False
    }


@router.post("/correlate", summary="Evaluate Evidence Correlation Between Two Cases")
def correlate_cases(req: CorrelationRequest):
    """
    Evaluates explainable deterministic correlation between two cases.
    Returns correlation score, confidence, and itemized reasons without altering database state.
    """
    # Resolve case A
    cases_a = supabase.query("cases", select="*", filters={"case_number": f"eq.{req.case_id_a}"})
    if not cases_a:
        cases_a = supabase.query("cases", select="*", filters={"id": f"eq.{req.case_id_a}"})
    if not cases_a:
        raise HTTPException(status_code=404, detail=f"Case {req.case_id_a} not found")
    case_a = cases_a[0]
    id_a = case_a.get("id") or case_a.get("case_number")

    # Resolve case B
    cases_b = supabase.query("cases", select="*", filters={"case_number": f"eq.{req.case_id_b}"})
    if not cases_b:
        cases_b = supabase.query("cases", select="*", filters={"id": f"eq.{req.case_id_b}"})
    if not cases_b:
        raise HTTPException(status_code=404, detail=f"Case {req.case_id_b} not found")
    case_b = cases_b[0]
    id_b = case_b.get("id") or case_b.get("case_number")

    # Fetch context
    email_a = (supabase.query("emails", select="*", filters={"case_id": f"eq.{id_a}"}) or [{}])[0]
    email_b = (supabase.query("emails", select="*", filters={"case_id": f"eq.{id_b}"}) or [{}])[0]
    obs_a = supabase.query("iocs", select="*", filters={"case_id": f"eq.{id_a}"})
    obs_b = supabase.query("iocs", select="*", filters={"case_id": f"eq.{id_b}"})
    infra_a = (supabase.query("infrastructure_intelligence", select="*", filters={"case_id": f"eq.{id_a}"}) or [{}])[0]
    infra_b = (supabase.query("infrastructure_intelligence", select="*", filters={"case_id": f"eq.{id_b}"}) or [{}])[0]

    result = campaign_service.evaluate_correlation(
        case_a=case_a,
        case_b=case_b,
        email_a=email_a,
        email_b=email_b,
        observables_a=obs_a,
        observables_b=obs_b,
        infra_a=infra_a,
        infra_b=infra_b
    )

    return {
        "case_a": case_a.get("case_number"),
        "case_b": case_b.get("case_number"),
        "correlation": result,
        "attribution_boundary": "Correlation score indicates observable infrastructure/behavioral overlap. Physical actor identity is not established.",
        "is_simulated_data": False
    }
