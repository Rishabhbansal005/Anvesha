"""
ANVESH Threat Intelligence & Real Global Search endpoints.
Strict Zero-Fabrication Architecture:
Returns real indicator evaluations from IntelligenceService and real Supabase records.
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Query, HTTPException
from app.database.supabase_client import supabase
from app.services.intelligence_service import intelligence_service

router = APIRouter()


@router.get("/search", summary="Real Global Search across Investigations & Indicators")
def global_search(q: str = Query(..., min_length=1, description="Query string")):
    """
    Real global search querying Supabase records.
    Searches cases, emails, and IOCs. Zero fake results.
    """
    clean_q = q.strip()
    results = []

    # Search cases in Supabase
    cases = supabase.query("cases", select="id,case_number,title,risk_score,status", limit=20)
    for c in cases:
        case_num = c.get("case_number", "")
        title = c.get("title", "")
        if clean_q.lower() in case_num.lower() or clean_q.lower() in title.lower():
            results.append({
                "type": "CASE",
                "id": case_num,
                "title": title,
                "subtitle": f"Risk: {c.get('risk_score')}/100 · Status: {c.get('status')}",
                "entity_id": c.get("id") or case_num
            })

    # Search IOCs / Observables in Supabase
    iocs = supabase.query("iocs", select="id,ioc_type,value,reputation_score,case_id", limit=20)
    for i in iocs:
        val = i.get("value", "")
        if clean_q.lower() in val.lower():
            results.append({
                "type": "IOC",
                "id": val,
                "title": f"[{i.get('ioc_type')}] {val}",
                "subtitle": f"Observable linked to case {i.get('case_id')}",
                "entity_id": i.get("id") or val
            })

    return {
        "query": clean_q,
        "results": results,
        "total": len(results),
        "is_simulated_data": False
    }


@router.get("/ip/{ip}", summary="Deterministic IP Classification & Intelligence")
def lookup_ip(ip: str):
    """
    Deterministic IP network classification via IntelligenceService.
    Distinguishes RFC1918 private vs public routable IPs.
    Returns status='UNAVAILABLE' for external reputation if unconfigured.
    """
    res = intelligence_service.lookup_ip(ip)
    if res["status"] == "INVALID":
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return res


@router.get("/domain/{domain}", summary="Domain Analysis & Lookalike Detection")
def lookup_domain(domain: str):
    """
    Lexical and homoglyph analysis for suspicious lookalike domains.
    Returns status='UNAVAILABLE' for external WHOIS/reputation if unconfigured.
    """
    res = intelligence_service.lookup_domain(domain)
    if res["status"] == "INVALID":
        raise HTTPException(status_code=400, detail="Invalid domain name format")
    return res
