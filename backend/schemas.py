from pydantic import BaseModel
from typing import Optional, Dict, Any

class SettingsUpdate(BaseModel):
    alert_threshold: Optional[float] = None
    logging_enabled: Optional[bool] = None

class FlowFeatures(BaseModel):
    proto: str
    sport: int
    dport: int
    pkts_tot: int
    bytes_tot: int
    dur: float
    rate_pps: float
    rate_bps: float
    tcp_flags: str
    dir_client_to_server: int

class TrafficLog(BaseModel):
    timestamp: float
    src: str
    dst: str
    features: Dict[str, Any]
    score: float
    label: int  # predicted {0,1}

class Alert(BaseModel):
    timestamp: float
    src: str
    dst: str
    severity: str
    score: float
    details: Dict[str, Any]
