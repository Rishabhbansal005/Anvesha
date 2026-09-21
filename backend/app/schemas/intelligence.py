"""
Pydantic schemas for Threat Intelligence & IOC Lookups.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class IOCLookupResponse(BaseModel):
    ioc_type: str # IP, DOMAIN, URL, HASH
    value: str
    reputation_score: int # 0 to 100
    is_malicious: bool
    verdict: str
    
    # Network / Geolocation details (when applicable)
    country_name: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    
    # Domain details (when applicable)
    registrar: Optional[str] = None
    is_lookalike: Optional[bool] = None
    target_impersonated: Optional[str] = None
    
    # Related case associations
    related_cases: List[str] = []
    related_campaigns: List[str] = []
    
    source: str = "LOCAL_REPUTATION_CACHE"
    fallback_active: bool = False
    disclaimer: str = "Geolocation indicates registered IP allocation, not confirmed human identity."
