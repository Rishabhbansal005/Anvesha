"""
Dashboard stats and telemetry schemas answering the 4 core investigator questions.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class ThreatDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class RecentActivityItem(BaseModel):
    id: str
    timestamp: str
    type: str
    description: str
    severity: str


class DashboardOverviewResponse(BaseModel):
    # 1. What is happening?
    total_emails_analyzed: int
    active_threat_level: str
    threat_trend_percentage: float
    threat_distribution: ThreatDistribution
    
    # 2. What needs attention?
    unreviewed_alerts_count: int
    critical_cases_count: int
    urgent_actions_required: List[Dict[str, Any]]
    
    # 3. What is connected?
    active_campaigns_count: int
    correlated_iocs_count: int
    primary_observed_asns: List[str]
    
    # 4. What changed?
    recent_activity: List[RecentActivityItem]
    
    # System meta
    is_simulated_data: bool = True
    system_status: str = "OPERATIONAL"
