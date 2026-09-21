"""
Health check and diagnostic endpoint for ANVESH.
"""
from fastapi import APIRouter
from app.core.config import settings
from app.database.supabase_client import supabase

router = APIRouter()


@router.get("/health", summary="ANVESH Health & Diagnostic Status")
def health_check():
    supabase_connected = supabase.ping()
    return {
        "status": "HEALTHY",
        "service": settings.PROJECT_NAME,
        "subtitle": settings.PROJECT_SUBTITLE,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "problem_statement": settings.PROBLEM_STATEMENT,
        "supabase_connected": supabase_connected,
        "supabase_endpoint": settings.SUPABASE_URL,
        "mock_data_active": False,
        "modules": {
            "forensics": "REAL_RFC822_ENGINE",
            "risk_engine": "ACTIVE_EXPLAINABLE_SCORING",
            "evidence_ledger": "ACTIVE_SHA256_CHAIN",
            "network_intrusion_model4": "ACTIVE_42_FEATURE_ENGINE",
            "data_source": "SUPABASE_POSTGREST" if supabase_connected else "STANDBY"
        }
    }
