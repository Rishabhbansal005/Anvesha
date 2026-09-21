from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional
from app.schemas.network import NetworkTelemetryRequest, NetworkTelemetryResult
from app.services.network_intrusion_service import get_network_intrusion_service
from app.services.scapy_network_service import get_scapy_service

router = APIRouter()


class ScapyCraftRequest(BaseModel):
    scenario: str = "syn_flood"


@router.post("/analyze", response_model=NetworkTelemetryResult, summary="Analyze 42-Feature Network Telemetry")
def analyze_network_telemetry(payload: NetworkTelemetryRequest):
    """
    Evaluates connection and transport telemetry across the 41 features trained on NSL-KDD benchmark.
    Returns anomaly classification, threat score (0-100), severity, and key active telemetry features.
    """
    service = get_network_intrusion_service()
    if not service.available:
        raise HTTPException(status_code=503, detail="Model 4 (network_intrusion_v1) is unavailable.")

    result = service.analyze_telemetry(payload.model_dump())
    return NetworkTelemetryResult(**result)


@router.get("/status", summary="Model 4 Health & Metadata")
def get_model_status():
    """Returns Model 4 verification status, SHA-256 signature, and training benchmarks."""
    service = get_network_intrusion_service()
    if not service.available or service.predictor is None:
        return {
            "status": "UNAVAILABLE",
            "model_name": "network_intrusion_v1",
            "features": 41
        }
    return {
        "status": "ACTIVE",
        "model_name": "network_intrusion_v1",
        "model_version": "1.0.0",
        "features_count": 41,
        "metadata": service.predictor.metadata
    }


@router.get("/scapy/status", summary="Scapy Network Engine Status")
def get_scapy_status():
    """Returns Scapy engine status, version, and supported packet dissection protocols."""
    engine = get_scapy_service()
    return engine.get_status()


@router.post("/scapy/craft-test", summary="Scapy Raw Packet Craft & Model 5 Dissection")
def craft_and_analyze_packets(payload: ScapyCraftRequest):
    """
    Crafts genuine Scapy IP/TCP/ICMP packets for the given attack or benign scenario,
    dissects the raw protocol layers, computes KDD connection features, and evaluates with Model 5.
    """
    engine = get_scapy_service()
    result = engine.craft_and_analyze(payload.scenario)
    return result


@router.post("/pcap/analyze", summary="Upload & Analyze PCAP Packet Capture via Scapy")
async def analyze_pcap_upload(file: UploadFile = File(...)):
    """
    Parses an uploaded .pcap or .pcapng Wireshark network capture using Scapy,
    extracts connection sessions, and classifies each flow against Model 5.
    """
    if not file.filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap network capture files are supported.")

    content = await file.read()
    if len(content) > 20 * 1024 * 1024:  # 20MB limit
        raise HTTPException(status_code=400, detail="PCAP file exceeds 20MB limit.")

    engine = get_scapy_service()
    result = engine.analyze_pcap_bytes(content, file.filename)
    return result


class EngineStartRequest(BaseModel):
    interface_id: Optional[str] = None
    interface: Optional[str] = None


class SimulationExportRequest(BaseModel):
    scenario: str = "syn_flood"


@router.get("/interfaces", summary="List Available Network Capture Interfaces")
def get_capture_interfaces():
    """Returns all network interfaces detected on the host OS with capture driver status."""
    engine = get_scapy_service()
    return engine.get_interfaces()


@router.post("/engine/start", summary="Start Live Engine 5 Passive Network Capture")
def start_engine_capture(payload: Optional[EngineStartRequest] = None):
    """Starts the Scapy passive network sniffing worker on the selected or default interface."""
    engine = get_scapy_service()
    iface = (payload.interface_id or payload.interface) if payload else None
    return engine.start_engine(interface_id=iface)


@router.post("/engine/stop", summary="Stop Live Engine 5 Passive Capture")
def stop_engine_capture():
    """Stops the active Scapy capture worker cleanly and preserves session metrics."""
    engine = get_scapy_service()
    return engine.stop_engine()


@router.post("/engine/reset", summary="Reset Engine 5 Live Session Telemetry")
def reset_engine_telemetry():
    """Clears live counters, alerts, and captured activity events without deleting historical logs."""
    engine = get_scapy_service()
    return engine.reset_engine()


@router.get("/engine/status", summary="Engine 5 Real-Time Operational Status")
def get_engine_operational_status():
    """Returns live Engine 5 operational metrics, counters, and current threat state."""
    engine = get_scapy_service()
    return engine.get_status()


@router.get("/engine/events", summary="Engine 5 Live Stream Events & Alerts")
def get_engine_stream_events():
    """Returns recent captured/analyzed packet flows and active alerts."""
    engine = get_scapy_service()
    return engine.get_events()


@router.post("/simulation/export-pcap", summary="Export In-Memory Simulation to Wireshark PCAP")
def export_simulation_pcap(payload: SimulationExportRequest):
    """
    Saves in-memory crafted Scapy scenario packets directly to a Wireshark-compatible .pcap file.
    Does NOT transmit any packets onto the physical network.
    """
    engine = get_scapy_service()
    return engine.export_simulation_pcap(payload.scenario)


@router.post("/engine/simulate-demo", summary="Stream Safe Demo Simulation into Live Engine 5")
def run_safe_demo_simulation(payload: SimulationExportRequest):
    """
    Runs an in-memory simulation and feeds resulting flows into the live dashboard state.
    Used as an interactive fallback when Npcap/libpcap driver is not installed.
    """
    engine = get_scapy_service()
    return engine.run_safe_simulation_stream(payload.scenario)

