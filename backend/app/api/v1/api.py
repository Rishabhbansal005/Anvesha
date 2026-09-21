"""
API v1 Router registry aggregating all operational endpoints.
"""
from fastapi import APIRouter
from app.api.v1.endpoints import health, stats, cases, alerts, intelligence, campaigns, evidence, emails, network

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health & Diagnostics"])
api_router.include_router(stats.router, prefix="/stats", tags=["Dashboard Telemetry"])
api_router.include_router(cases.router, prefix="/cases", tags=["Investigations & Cases"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alert Triage"])
api_router.include_router(intelligence.router, prefix="/intelligence", tags=["Threat Intelligence & IOCs"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["Threat Campaigns"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["Evidence Chain Ledger"])
api_router.include_router(emails.router, prefix="/emails", tags=["Email Forensics Engine"])
api_router.include_router(network.router, prefix="/network", tags=["Network Telemetry & Intrusion (Model 4)"])
