"""
Pydantic Schemas for ANVESH Model 4 (42-Feature Network Intrusion & Telemetry Engine).
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class NetworkTelemetryRequest(BaseModel):
    """Network connection telemetry (can accept a full or partial feature dictionary)."""
    duration: float = Field(default=0.0, description="Connection duration in seconds")
    protocol_type: str = Field(default="tcp", description="Protocol: tcp, udp, icmp")
    service: str = Field(default="http", description="Network service: http, smtp, private, etc.")
    flag: str = Field(default="SF", description="Status flag: SF, REJ, S0, etc.")
    src_bytes: float = Field(default=0.0, description="Source bytes")
    dst_bytes: float = Field(default=0.0, description="Destination bytes")
    land: str = Field(default="0", description="Land attack flag")
    wrong_fragment: float = Field(default=0.0)
    urgent: float = Field(default=0.0)
    hot: float = Field(default=0.0)
    num_failed_logins: float = Field(default=0.0)
    logged_in: str = Field(default="0")
    num_compromised: float = Field(default=0.0)
    root_shell: float = Field(default=0.0)
    su_attempted: float = Field(default=0.0)
    num_root: float = Field(default=0.0)
    num_file_creations: float = Field(default=0.0)
    num_shells: float = Field(default=0.0)
    num_access_files: float = Field(default=0.0)
    num_outbound_cmds: float = Field(default=0.0)
    is_host_login: str = Field(default="0")
    is_guest_login: str = Field(default="0")
    count: float = Field(default=1.0)
    srv_count: float = Field(default=1.0)
    serror_rate: float = Field(default=0.0)
    srv_serror_rate: float = Field(default=0.0)
    rerror_rate: float = Field(default=0.0)
    srv_rerror_rate: float = Field(default=0.0)
    same_srv_rate: float = Field(default=1.0)
    diff_srv_rate: float = Field(default=0.0)
    srv_diff_host_rate: float = Field(default=0.0)
    dst_host_count: float = Field(default=255.0)
    dst_host_srv_count: float = Field(default=255.0)
    dst_host_same_srv_rate: float = Field(default=1.0)
    dst_host_diff_srv_rate: float = Field(default=0.0)
    dst_host_same_src_port_rate: float = Field(default=0.0)
    dst_host_srv_diff_host_rate: float = Field(default=0.0)
    dst_host_serror_rate: float = Field(default=0.0)
    dst_host_srv_serror_rate: float = Field(default=0.0)
    dst_host_rerror_rate: float = Field(default=0.0)
    dst_host_srv_rerror_rate: float = Field(default=0.0)


class FeatureContribution(BaseModel):
    feature: str
    importance: float
    observed_value: Any


class NetworkTelemetryResult(BaseModel):
    model_name: str = "network_intrusion_v1"
    model_version: str = "1.0.0"
    anomaly_detected: bool
    threat_score: int
    raw_probability: float
    severity: str
    confidence: str
    top_contributing_features: List[FeatureContribution] = []
    attribution_boundary: str = "Network & Relay Telemetry Evidence Only; Actor Identity: NOT ESTABLISHED"
