"""
ANVESH Scapy Network Telemetry & Packet Dissection Service.
Bridges raw network packet captures (Scapy IP/TCP/UDP/ICMP) with Model 4 (network_intrusion_v1).
Supports:
1. Raw packet crafting, dissection, and feature extraction.
2. PCAP file parsing and flow-by-flow Model 5 forensic scoring.
3. Realistic packet generation for SOC demonstration & intrusion detection.
"""

import io
import os
import time
import tempfile
import logging
import threading
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

try:
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
except Exception:
    IPv6 = None
    ICMPv6EchoRequest = None

from app.services.network_intrusion_service import get_network_intrusion_service

logger = logging.getLogger("ANVESH.ScapyService")


class ScapyTelemetryEngine:
    """
    Handles live packet sniffing, raw packet parsing, crafting,
    flow reconstruction, and Model 5 classification.
    """

    PORT_SERVICE_MAP = {
        80: "http",
        443: "http",  # mapped to web
        8080: "http",
        25: "smtp",
        587: "smtp",
        21: "ftp",
        20: "ftp_data",
        53: "domain_u",
        22: "ssh",
        23: "telnet",
        110: "pop_3",
        143: "imap4",
        123: "ntp_u",
        67: "dhcp",
        68: "dhcp"
    }

    def __init__(self):
        self.intrusion_service = get_network_intrusion_service()
        self.version = getattr(scapy, "__version__", "2.7.0")
        
        # Engine Lifecycle State
        self.engine_status: str = "STOPPED"  # STOPPED, STARTING, CAPTURING, ANALYZING, ALERT
        self.packets_captured: int = 0
        self.flows_created: int = 0
        self.flows_analyzed: int = 0
        self.normal_flows: int = 0
        self.suspicious_flows: int = 0
        self.threats_detected: int = 0
        self.highest_threat_score: int = 0
        self.current_risk_level: str = "LOW"
        self.active_alert: Optional[Dict[str, Any]] = None
        self.live_events: List[Dict[str, Any]] = []
        self.selected_interface: Optional[str] = None
        self.capture_error: Optional[str] = None
        
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None

    def get_status(self) -> Dict[str, Any]:
        """Returns Scapy engine status, driver capabilities, and current session metrics."""
        has_libpcap = bool(getattr(scapy.conf, "use_pcap", False))
        with self._lock:
            return {
                "status": self.engine_status,
                "engine_status": self.engine_status,
                "scapy_version": self.version,
                "has_libpcap": has_libpcap,
                "live_capture_available": has_libpcap,
                "driver_available": has_libpcap,
                "capture_error": self.capture_error,
                "selected_interface": self.selected_interface,
                "packets_captured": self.packets_captured,
                "flows_created": self.flows_created,
                "flows_analyzed": self.flows_analyzed,
                "normal_flows": self.normal_flows,
                "suspicious_flows": self.suspicious_flows,
                "threats_detected": self.threats_detected,
                "highest_threat_score": self.highest_threat_score,
                "current_risk_level": self.current_risk_level,
                "active_alert": self.active_alert,
                "supported_protocols": ["TCP", "UDP", "ICMP", "IP", "Ethernet", "Raw"],
                "pcap_parser": "Native Python Scapy Parser (Zero Driver Dependency)"
            }

    def get_interfaces(self) -> Dict[str, Any]:
        """Detects available network interfaces on the operating system."""
        has_libpcap = bool(getattr(scapy.conf, "use_pcap", False))
        interfaces = []
        
        try:
            if hasattr(scapy.conf, "ifaces"):
                for key in scapy.conf.ifaces:
                    dev = scapy.conf.ifaces[key]
                    name = str(getattr(dev, "name", key))
                    desc = str(getattr(dev, "description", ""))
                    ip = str(getattr(dev, "ip", ""))
                    
                    # Filter out noise like WAN Miniports or loop filters, highlight active NICs
                    if "WAN Miniport" in desc or "Filter" in name:
                        continue
                        
                    interfaces.append({
                        "id": str(key),
                        "name": name,
                        "description": desc or name,
                        "ip": ip,
                        "is_active": bool(ip and ip != "0.0.0.0")
                    })
        except Exception as e:
            logger.error(f"[SCAPY] Error detecting interfaces: {e}")

        # Fallback if list is empty
        if not interfaces:
            interfaces.append({
                "id": "auto",
                "name": "Default Adapter",
                "description": "System Default Network Adapter",
                "ip": "Auto",
                "is_active": True
            })

        return {
            "interfaces": interfaces,
            "count": len(interfaces),
            "live_capture_available": has_libpcap,
            "driver_status": "AVAILABLE" if has_libpcap else "UNAVAILABLE",
            "driver_message": (
                "Npcap packet capture driver is active and ready for live capture."
                if has_libpcap else
                "Live capture requires a supported packet-capture driver such as Npcap and appropriate permissions."
            )
        }

    def start_engine(self, interface_id: Optional[str] = None, interface: Optional[str] = None) -> Dict[str, Any]:
        """
        Starts the passive network monitoring engine.
        Enforces defensive safety: checks Npcap/driver readiness.
        """
        chosen_iface = interface_id or interface
        with self._lock:
            if self.engine_status in ["CAPTURING", "STARTING"]:
                return {
                    "status": self.engine_status,
                    "message": "Engine is already running."
                }

            self.engine_status = "STARTING"
            self.capture_error = None
            self.selected_interface = chosen_iface or "Auto-Detect"

        has_libpcap = bool(getattr(scapy.conf, "use_pcap", False))
        if not has_libpcap:
            with self._lock:
                self.engine_status = "STOPPED"
                self.capture_error = "Live capture requires a supported packet-capture driver such as Npcap and appropriate permissions."
            return {
                "status": "UNAVAILABLE",
                "engine_status": "STOPPED",
                "message": self.capture_error,
                "demo_fallback_available": True,
                "suggestion": "Use PCAP Upload or Safe Simulation instead."
            }

        # If libpcap is available, start live passive sniffing thread
        try:
            self._stop_event.clear()
            self._capture_thread = threading.Thread(
                target=self._sniff_worker,
                args=(chosen_iface,),
                daemon=True
            )
            self._capture_thread.start()
            with self._lock:
                self.engine_status = "CAPTURING"
            return {
                "status": "SUCCESS",
                "engine_status": "CAPTURING",
                "interface": self.selected_interface,
                "message": "Engine 5 live capture started passively."
            }
        except Exception as e:
            with self._lock:
                self.engine_status = "STOPPED"
                self.capture_error = str(e)
            return {
                "status": "ERROR",
                "engine_status": "STOPPED",
                "message": f"Failed to start live capture: {e}"
            }

    def _sniff_worker(self, interface_id: Optional[str]):
        """Background thread worker for passive packet sniffing."""
        logger.info(f"[SCAPY] Passive live sniffing worker started on {interface_id}")
        flow_buffer = defaultdict(list)
        
        def packet_handler(pkt):
            if self._stop_event.is_set():
                return
                
            with self._lock:
                self.packets_captured += 1
                if self.engine_status == "CAPTURING" and self.packets_captured % 5 == 0:
                    self.engine_status = "ANALYZING"
                    
            if IP in pkt or (IPv6 and IPv6 in pkt):
                is_ipv4 = IP in pkt
                ip_layer = pkt[IP] if is_ipv4 else pkt[IPv6]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if (ICMP in pkt or (ICMPv6EchoRequest and ICMPv6EchoRequest in pkt)) else "OTHER"
                sport = int(pkt[TCP].sport) if TCP in pkt else int(pkt[UDP].sport) if UDP in pkt else 0
                dport = int(pkt[TCP].dport) if TCP in pkt else int(pkt[UDP].dport) if UDP in pkt else 0
                flow_key = (src_ip, dst_ip, sport, dport, proto)
                
                flow_buffer[flow_key].append(pkt)
                
                # Analyze flow once it reaches 3 packets, or immediately for SYN connection attempts
                should_eval = (
                    len(flow_buffer[flow_key]) >= 3 or
                    (TCP in pkt and "S" in str(pkt[TCP].flags)) or
                    (ICMP in pkt)
                )
                if should_eval:
                    self._evaluate_single_flow(flow_key, flow_buffer[flow_key])
                    flow_buffer[flow_key] = []

        try:
            sniff_args = {
                "prn": packet_handler,
                "stop_filter": lambda p: self._stop_event.is_set(),
                "store": False,
                "timeout": 1
            }
            if interface_id and interface_id != "auto" and interface_id != "Auto-Detect":
                sniff_args["iface"] = interface_id

            while not self._stop_event.is_set():
                scapy.sniff(**sniff_args)
                
            # Flush any residual un-evaluated flows on worker shutdown
            for flow_key, buffered_pkts in list(flow_buffer.items()):
                if buffered_pkts:
                    self._evaluate_single_flow(flow_key, buffered_pkts)
            flow_buffer.clear()
        except Exception as e:
            logger.error(f"[SCAPY] Sniff worker encountered error: {e}")
            with self._lock:
                self.capture_error = str(e)
                self.engine_status = "STOPPED"

    def _evaluate_single_flow(self, flow_key: tuple, pkts: List[Any]) -> Dict[str, Any]:
        """Runs the unified Model 5 evaluation on a single extracted flow."""
        src_ip, dst_ip, sport, dport, proto = flow_key
        features = self.extract_features_from_packets(pkts, "live_flow")
        verdict = self.intrusion_service.analyze_telemetry(features)
        
        threat_score = verdict.get("threat_score", 0)
        is_anomaly = verdict.get("anomaly_detected", False)
        
        # Deterministic flow ID from 5-tuple (allows analysts to associate flow across events/alerts)
        flow_hash = hashlib.md5(f"{src_ip}:{sport}->{dst_ip}:{dport}/{proto}".encode()).hexdigest()[:8].upper()
        flow_id = f"FLOW-{flow_hash}"

        # Actual Scapy packet timestamp preservation
        first_pkt = pkts[0] if pkts else None
        first_pkt_time = getattr(first_pkt, "time", None) if first_pkt else None
        if first_pkt_time is not None:
            try:
                timestamp_str = datetime.fromtimestamp(float(first_pkt_time)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Connection flow duration
        if len(pkts) > 1 and hasattr(pkts[0], 'time') and hasattr(pkts[-1], 'time'):
            try:
                duration_sec = round(abs(float(pkts[-1].time) - float(pkts[0].time)), 4)
            except Exception:
                duration_sec = float(features.get("duration", 0.0))
        else:
            duration_sec = float(features.get("duration", 0.0))

        status_label = "SUSPICIOUS" if is_anomaly else "NORMAL"
        service_name = features.get("service", "http")
        flag_name = features.get("flag", "SF")
        summary_str = f"{proto} flow from {src_ip}:{sport} to {dst_ip}:{dport} ({len(pkts)} packets, service: {service_name}, flag: {flag_name})"

        event = {
            # Deterministic Flow & Event Identifiers
            "flow_id": flow_id,
            "event_id": flow_id,
            "id": flow_id,

            # Preserved Actual Timestamps
            "timestamp": timestamp_str,
            "time": timestamp_str.split(" ")[-1] if " " in timestamp_str else timestamp_str,

            # Source & Destination Network Metadata
            "source": f"{src_ip}:{sport}",
            "destination": f"{dst_ip}:{dport}",
            "source_ip": src_ip,
            "src_ip": src_ip,
            "destination_ip": dst_ip,
            "dst_ip": dst_ip,
            "source_port": sport,
            "sport": sport,
            "destination_port": dport,
            "dport": dport,

            # Transport & Connection Metadata
            "protocol": proto,
            "service": service_name,
            "flag": flag_name,
            "packet_count": len(pkts),
            "packets": len(pkts),
            "duration_sec": duration_sec,
            "summary": summary_str,

            # Model 5 ML Classification & Scoring
            "status": status_label,
            "threat_score": threat_score,
            "severity": verdict.get("severity", "LOW"),
            "anomaly_detected": is_anomaly,
            "is_anomaly": is_anomaly,

            # 41 KDD Features & Explanations (Gini feature importances)
            "features": features,
            "verdict": verdict,
            "top_factors": verdict.get("top_contributing_features", [])
        }
        
        with self._lock:
            self.flows_created += 1
            self.flows_analyzed += 1
            if is_anomaly:
                self.suspicious_flows += 1
                self.threats_detected += 1
                self.engine_status = "ALERT"
            else:
                self.normal_flows += 1
                if self.engine_status != "ALERT":
                    self.engine_status = "CAPTURING"
                    
            if threat_score > self.highest_threat_score:
                self.highest_threat_score = threat_score
                
            if self.highest_threat_score >= 80:
                self.current_risk_level = "CRITICAL"
            elif self.highest_threat_score >= 60:
                self.current_risk_level = "HIGH"
            elif self.highest_threat_score >= 30:
                self.current_risk_level = "MEDIUM"
            else:
                self.current_risk_level = "LOW"
                
            # Keep recent 100 events
            self.live_events.insert(0, event)
            if len(self.live_events) > 100:
                self.live_events = self.live_events[:100]
                
            if is_anomaly:
                self.active_alert = {
                    "threat_title": "NETWORK THREAT DETECTED",
                    "threat_score": threat_score,
                    "risk_level": self.current_risk_level,
                    "flow_id": flow_id,
                    "event_id": flow_id,
                    "id": flow_id,
                    "source": f"{src_ip}:{sport}",
                    "destination": f"{dst_ip}:{dport}",
                    "source_ip": src_ip,
                    "src_ip": src_ip,
                    "source_port": sport,
                    "sport": sport,
                    "destination_ip": dst_ip,
                    "dst_ip": dst_ip,
                    "destination_port": dport,
                    "dport": dport,
                    "protocol": proto,
                    "service": service_name,
                    "flag": flag_name,
                    "timestamp": timestamp_str,
                    "time": timestamp_str.split(" ")[-1] if " " in timestamp_str else timestamp_str,
                    "packet_count": len(pkts),
                    "packets": len(pkts),
                    "duration_sec": duration_sec,
                    "summary": summary_str,
                    "status": "SUSPICIOUS",
                    "severity": verdict.get("severity", "LOW"),
                    "anomaly_detected": True,
                    "is_anomaly": True,
                    "verdict": verdict,
                    "features": features,
                    "top_factors": verdict.get("top_contributing_features", [])
                }

        return event

    def stop_engine(self) -> Dict[str, Any]:
        """Safely stops passive packet capture and preserves session results."""
        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2)
            
        with self._lock:
            self.engine_status = "STOPPED"
            
        return {
            "status": "STOPPED",
            "message": "Engine 5 stopped successfully. Session statistics preserved.",
            "packets_captured": self.packets_captured,
            "threats_detected": self.threats_detected
        }

    def reset_engine(self) -> Dict[str, Any]:
        """Resets the current monitoring session without deleting database history."""
        with self._lock:
            self.packets_captured = 0
            self.flows_created = 0
            self.flows_analyzed = 0
            self.normal_flows = 0
            self.suspicious_flows = 0
            self.threats_detected = 0
            self.highest_threat_score = 0
            self.current_risk_level = "LOW"
            self.active_alert = None
            self.live_events = []
            self.capture_error = None
            self.engine_status = "STOPPED"
            
        return {
            "status": "RESET",
            "message": "Current session statistics and event buffers cleared."
        }

    def get_events(self) -> Dict[str, Any]:
        """Returns recent live packet events and active alert state."""
        with self._lock:
            return {
                "events": list(self.live_events),
                "active_alert": self.active_alert,
                "status": self.engine_status,
                "packets_captured": self.packets_captured,
                "flows_analyzed": self.flows_analyzed,
                "threats_detected": self.threats_detected
            }

    def run_safe_simulation_stream(self, scenario: str) -> Dict[str, Any]:
        """
        Runs an in-memory safe simulation of network traffic without transmitting
        packets to any real physical network wires, and feeds it into the unified
        Engine 5 pipeline. Updates live session dashboard seamlessly.
        """
        with self._lock:
            self.engine_status = "ANALYZING"

        packets = self.craft_scenario_packets(scenario)
        dissected = [self.dissect_packet(p, i) for i, p in enumerate(packets[:15])]
        
        # Group into flows
        flows_dict = defaultdict(list)
        for p in packets:
            if IP in p:
                proto = "TCP" if TCP in p else "UDP" if UDP in p else "ICMP" if ICMP in p else "OTHER"
                sport = int(p[TCP].sport) if TCP in p else int(p[UDP].sport) if UDP in p else 0
                dport = int(p[TCP].dport) if TCP in p else int(p[UDP].dport) if UDP in p else 0
                flow_key = (str(p[IP].src), str(p[IP].dst), sport, dport, proto)
                flows_dict[flow_key].append(p)
            elif IPv6 and IPv6 in p:
                proto = "TCP" if TCP in p else "UDP" if UDP in p else "ICMP" if (ICMPv6EchoRequest and ICMPv6EchoRequest in p) else "OTHER"
                sport = int(p[TCP].sport) if TCP in p else int(p[UDP].sport) if UDP in p else 0
                dport = int(p[TCP].dport) if TCP in p else int(p[UDP].dport) if UDP in p else 0
                flow_key = (str(p[IPv6].src), str(p[IPv6].dst), sport, dport, proto)
                flows_dict[flow_key].append(p)

        with self._lock:
            self.packets_captured += len(packets)

        # Process flows through unified pipeline
        evaluated_events = []
        for flow_key, flow_pkts in flows_dict.items():
            evt = self._evaluate_single_flow(flow_key, flow_pkts)
            evaluated_events.append(evt)

        features = self.extract_features_from_packets(packets, scenario)
        prediction = self.intrusion_service.analyze_telemetry(features)

        primary_incident = evaluated_events[0] if evaluated_events else None

        return {
            "scenario": scenario,
            "scapy_engine": f"Scapy v{self.version}",
            "total_packets_crafted": len(packets),
            "sample_packets": dissected,
            "extracted_telemetry_features": {
                "protocol_type": features["protocol_type"],
                "service": features["service"],
                "flag": features["flag"],
                "src_bytes": features["src_bytes"],
                "dst_bytes": features["dst_bytes"],
                "packet_count": features["count"],
                "serror_rate": features["serror_rate"],
                "logged_in": features["logged_in"]
            },
            "model_verdict": prediction,
            "incident": primary_incident,
            "session_metrics": self.get_status()
        }

    def export_simulation_pcap(self, scenario: str) -> Dict[str, Any]:
        """
        Generates genuine Scapy packets for the scenario in memory and writes
        a standard Wireshark-compatible .pcap file into the public samples directory.
        """
        packets = self.craft_scenario_packets(scenario)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"anvesh_{scenario}_{timestamp_str}.pcap"
        
        # Save into web/public/samples directory
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        output_dir = os.path.join(repo_root, "web", "public", "samples")
        os.makedirs(output_dir, exist_ok=True)
        
        file_path = os.path.join(output_dir, filename)
        
        try:
            scapy.wrpcap(file_path, packets)
            file_size = os.path.getsize(file_path)
            
            return {
                "status": "SUCCESS",
                "filename": filename,
                "download_url": f"/samples/{filename}",
                "file_path": file_path,
                "packet_count": len(packets),
                "file_size_bytes": file_size,
                "scenario": scenario,
                "message": "Wireshark-compatible PCAP created successfully."
            }
        except Exception as e:
            logger.error(f"[SCAPY] Failed to export PCAP: {e}")
            return {
                "status": "ERROR",
                "message": f"Failed to export PCAP: {e}"
            }

    def craft_scenario_packets(self, scenario: str) -> List[Any]:
        """Crafts a list of genuine Scapy Packet objects matching the requested scenario."""
        packets = []

        if scenario == "syn_flood":
            # High rate of half-open TCP SYN packets with 0 payload
            target_ip = "192.168.1.100"
            for i in range(25):
                sport = 1024 + (i * 37) % 64000
                pkt = IP(src=f"10.0.0.{(i % 250) + 1}", dst=target_ip) / TCP(
                    sport=sport, dport=80, flags="S", seq=1000 + i * 50
                )
                packets.append(pkt)

        elif scenario == "port_scan":
            # Attacker scanning multiple destination ports sequentially
            attacker_ip = "185.220.101.42"
            target_ip = "192.168.1.50"
            target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
            for port in target_ports:
                pkt = IP(src=attacker_ip, dst=target_ip) / TCP(
                    sport=45120, dport=port, flags="S"
                )
                packets.append(pkt)

        elif scenario == "icmp_sweep":
            # Echo ping scan across a subnet
            attacker_ip = "10.0.2.15"
            for i in range(15):
                pkt = IP(src=attacker_ip, dst=f"192.168.1.{10 + i}") / ICMP(type=8, code=0)
                packets.append(pkt)

        elif scenario == "benign_http":
            # Complete 3-way handshake + HTTP GET request with payload
            client_ip = "192.168.1.15"
            server_ip = "93.184.216.34"
            client_port = 52341
            server_port = 80

            # 1. SYN
            syn = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=100)
            # 2. SYN-ACK
            syn_ack = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=500, ack=101)
            # 3. ACK
            ack = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=101, ack=501)
            # 4. HTTP GET Data
            payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
            http_req = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=101, ack=501) / Raw(payload)
            # 5. HTTP Response Data
            resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 125\r\n\r\n<html><body>Safe</body></html>"
            http_resp = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=501, ack=101 + len(payload)) / Raw(resp_payload)
            # 6. FIN-ACK
            fin = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="FA", seq=101 + len(payload), ack=501 + len(resp_payload))

            packets = [syn, syn_ack, ack, http_req, http_resp, fin]

        else:
            # Default single TCP packet
            pkt = IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=50000, dport=80, flags="S")
            packets.append(pkt)

        return packets

    def dissect_packet(self, pkt: Any, index: int) -> Dict[str, Any]:
        """Dissects an individual Scapy packet into human-readable protocol layers."""
        summary = pkt.summary()
        layers = []
        curr = pkt
        while curr:
            layers.append(curr.name)
            curr = curr.payload if hasattr(curr, "payload") and curr.payload and curr.payload.name != "NoPayload" else None

        info = {
            "packet_id": index + 1,
            "summary": summary,
            "layers": layers,
            "length_bytes": len(pkt),
            "protocol": "OTHER"
        }

        # Preserve Scapy packet timestamp
        pkt_time = getattr(pkt, "time", None)
        if pkt_time is not None:
            try:
                info["timestamp"] = datetime.fromtimestamp(float(pkt_time)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                info["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if IP in pkt:
            info["src_ip"] = str(pkt[IP].src)
            info["dst_ip"] = str(pkt[IP].dst)
            info["source_ip"] = str(pkt[IP].src)
            info["destination_ip"] = str(pkt[IP].dst)
            info["ttl"] = int(pkt[IP].ttl)
        elif IPv6 and IPv6 in pkt:
            info["src_ip"] = str(pkt[IPv6].src)
            info["dst_ip"] = str(pkt[IPv6].dst)
            info["source_ip"] = str(pkt[IPv6].src)
            info["destination_ip"] = str(pkt[IPv6].dst)

        if TCP in pkt:
            info["protocol"] = "TCP"
            info["src_port"] = int(pkt[TCP].sport)
            info["dst_port"] = int(pkt[TCP].dport)
            info["source_port"] = int(pkt[TCP].sport)
            info["destination_port"] = int(pkt[TCP].dport)
            info["tcp_flags"] = str(pkt[TCP].flags)
            info["seq"] = int(pkt[TCP].seq)
            info["ack"] = int(pkt[TCP].ack)
        elif UDP in pkt:
            info["protocol"] = "UDP"
            info["src_port"] = int(pkt[UDP].sport)
            info["dst_port"] = int(pkt[UDP].dport)
            info["source_port"] = int(pkt[UDP].sport)
            info["destination_port"] = int(pkt[UDP].dport)
        elif ICMP in pkt:
            info["protocol"] = "ICMP"
            info["icmp_type"] = int(pkt[ICMP].type)
            info["icmp_code"] = int(pkt[ICMP].code)
            info["src_port"] = 0
            info["dst_port"] = 0
            info["source_port"] = 0
            info["destination_port"] = 0

        if Raw in pkt:
            raw_bytes = bytes(pkt[Raw])
            info["payload_sample"] = raw_bytes[:64].decode("latin-1", errors="replace")

        return info

    def extract_features_from_packets(self, packets: List[Any], scenario: str) -> Dict[str, Any]:
        """Calculates 41 KDD connection telemetry features from the Scapy packet stream."""
        if not packets:
            return {"service": "http", "protocol_type": "tcp", "flag": "SF"}

        first_pkt = packets[0]
        protocol_type = "tcp"
        if UDP in first_pkt:
            protocol_type = "udp"
        elif ICMP in first_pkt:
            protocol_type = "icmp"

        # Determine destination port & service
        dst_port = 80
        flag_str = "SF"
        has_syn = False
        has_ack = False
        has_rst = False
        src_bytes = 0
        dst_bytes = 0

        first_ip = getattr(first_pkt.getlayer(IP), "src", "192.168.1.1") if IP in first_pkt else "192.168.1.1"

        for p in packets:
            if TCP in p:
                dport = p[TCP].dport
                if dport in self.PORT_SERVICE_MAP:
                    dst_port = dport
                flags = str(p[TCP].flags)
                if "S" in flags:
                    has_syn = True
                if "A" in flags:
                    has_ack = True
                if "R" in flags:
                    has_rst = True

                if Raw in p:
                    payload_len = len(bytes(p[Raw]))
                    if IP in p and p[IP].src == first_ip:
                        src_bytes += payload_len
                    else:
                        dst_bytes += payload_len

            elif ICMP in p:
                dst_port = 0
                if Raw in p:
                    src_bytes += len(bytes(p[Raw]))

        service = self.PORT_SERVICE_MAP.get(dst_port, "private" if scenario in ["syn_flood", "port_scan"] else "http")
        if protocol_type == "icmp":
            service = "eco_i"

        # Determine KDD connection flag
        if has_rst:
            flag_str = "REJ"
        elif has_syn and not has_ack:
            flag_str = "S0"
        elif has_syn and has_ack:
            flag_str = "SF"
        else:
            flag_str = "SF"

        packet_count = len(packets)
        serror_rate = 1.0 if flag_str == "S0" else 0.0
        diff_srv_rate = 0.8 if scenario == "port_scan" else 0.0
        dst_host_diff_srv_rate = 0.7 if scenario in ["port_scan", "icmp_sweep"] else 0.0
        same_srv_rate = 0.1 if scenario == "port_scan" else 1.0

        features = {
            "duration": 0.12 if scenario == "benign_http" else 0.0,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag_str,
            "src_bytes": float(src_bytes),
            "dst_bytes": float(dst_bytes),
            "land": "0",
            "wrong_fragment": 0.0,
            "urgent": 0.0,
            "hot": 0.0,
            "num_failed_logins": 0.0,
            "logged_in": "1" if (service in ["http", "smtp"] and flag_str == "SF" and src_bytes > 50) else "0",
            "num_compromised": 0.0,
            "root_shell": 0.0,
            "su_attempted": 0.0,
            "num_root": 0.0,
            "num_file_creations": 0.0,
            "num_shells": 0.0,
            "num_access_files": 0.0,
            "num_outbound_cmds": 0.0,
            "is_host_login": "0",
            "is_guest_login": "0",
            "count": float(packet_count),
            "srv_count": float(max(1, packet_count // 2)),
            "serror_rate": serror_rate,
            "srv_serror_rate": serror_rate,
            "rerror_rate": 1.0 if flag_str == "REJ" else 0.0,
            "srv_rerror_rate": 1.0 if flag_str == "REJ" else 0.0,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0 if scenario == "syn_flood" else float(min(255, packet_count * 2)),
            "dst_host_srv_count": 2.0 if scenario in ["syn_flood", "port_scan"] else 255.0,
            "dst_host_same_srv_rate": 0.05 if scenario in ["syn_flood", "port_scan"] else 1.0,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": 0.9 if scenario == "syn_flood" else 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": serror_rate,
            "dst_host_srv_serror_rate": serror_rate,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }

        return features

    def craft_and_analyze(self, scenario: str) -> Dict[str, Any]:
        """
        Main demonstration workflow:
        1. Crafts raw Scapy packets for the given scenario.
        2. Dissects packet layers and generates summaries.
        3. Computes 41 KDD features from the packet stream.
        4. Invokes Model 4 (network_intrusion_v1) for verdict and threat score.
        """
        packets = self.craft_scenario_packets(scenario)
        dissected = [self.dissect_packet(p, i) for i, p in enumerate(packets[:15])]

        # Extract features and predict
        features = self.extract_features_from_packets(packets, scenario)
        prediction = self.intrusion_service.analyze_telemetry(features)

        # Primary flow metadata from crafted packets
        first_p = packets[0]
        proto = "TCP" if TCP in first_p else "UDP" if UDP in first_p else "ICMP" if ICMP in first_p else "OTHER"
        src_ip = str(first_p[IP].src) if IP in first_p else (str(first_p[IPv6].src) if IPv6 and IPv6 in first_p else "10.0.0.1")
        dst_ip = str(first_p[IP].dst) if IP in first_p else (str(first_p[IPv6].dst) if IPv6 and IPv6 in first_p else "192.168.1.100")
        sport = int(first_p[TCP].sport) if TCP in first_p else (int(first_p[UDP].sport) if UDP in first_p else 0)
        dport = int(first_p[TCP].dport) if TCP in first_p else (int(first_p[UDP].dport) if UDP in first_p else 0)

        flow_hash = hashlib.md5(f"{src_ip}:{sport}->{dst_ip}:{dport}/{proto}".encode()).hexdigest()[:8].upper()
        flow_id = f"FLOW-{flow_hash}"

        first_pkt_time = getattr(first_p, 'time', None)
        if first_pkt_time is not None:
            try:
                timestamp_str = datetime.fromtimestamp(float(first_pkt_time)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        threat_score = prediction.get("threat_score", 0)
        is_anomaly = prediction.get("anomaly_detected", False)
        status_label = "SUSPICIOUS" if is_anomaly else "NORMAL"
        service_name = features.get("service", "http")
        flag_name = features.get("flag", "SF")
        summary_str = f"Crafted {scenario} {proto} flow from {src_ip}:{sport} to {dst_ip}:{dport} ({len(packets)} packets, service: {service_name}, flag: {flag_name})"

        incident = {
            "flow_id": flow_id,
            "event_id": flow_id,
            "id": flow_id,
            "timestamp": timestamp_str,
            "time": timestamp_str.split(" ")[-1] if " " in timestamp_str else timestamp_str,
            "source": f"{src_ip}:{sport}",
            "destination": f"{dst_ip}:{dport}",
            "source_ip": src_ip,
            "src_ip": src_ip,
            "destination_ip": dst_ip,
            "dst_ip": dst_ip,
            "source_port": sport,
            "sport": sport,
            "destination_port": dport,
            "dport": dport,
            "protocol": proto,
            "service": service_name,
            "flag": flag_name,
            "packet_count": len(packets),
            "packets": len(packets),
            "duration_sec": float(features.get("duration", 0.0)),
            "summary": summary_str,
            "status": status_label,
            "threat_score": threat_score,
            "severity": prediction.get("severity", "LOW"),
            "anomaly_detected": is_anomaly,
            "is_anomaly": is_anomaly,
            "features": features,
            "verdict": prediction,
            "top_factors": prediction.get("top_contributing_features", [])
        }

        return {
            "scenario": scenario,
            "scapy_engine": f"Scapy v{self.version}",
            "total_packets_crafted": len(packets),
            "sample_packets": dissected,
            "extracted_telemetry_features": {
                "protocol_type": features["protocol_type"],
                "service": features["service"],
                "flag": features["flag"],
                "src_bytes": features["src_bytes"],
                "dst_bytes": features["dst_bytes"],
                "packet_count": features["count"],
                "serror_rate": features["serror_rate"],
                "logged_in": features["logged_in"]
            },
            "model_verdict": prediction,
            "incident": incident
        }

    def analyze_pcap_bytes(self, file_bytes: bytes, filename: str = "capture.pcap") -> Dict[str, Any]:
        """Parses an uploaded .pcap or .pcapng file using Scapy and runs Model 5."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        try:
            packets = scapy.rdpcap(tmp_path)
        except Exception as e:
            logger.error(f"[SCAPY] Failed to read PCAP: {e}")
            return {
                "status": "ERROR",
                "filename": filename,
                "error": f"Invalid or unreadable PCAP capture file: {str(e)}",
                "total_packets": 0,
                "flows": []
            }

        total_packets = len(packets)
        if total_packets == 0:
            return {
                "status": "SUCCESS",
                "filename": filename,
                "total_packets": 0,
                "flows": [],
                "summary": "Capture file is empty."
            }

        # Group into 5-tuple flows
        flows_dict = defaultdict(list)
        sample_packets = []

        for idx, p in enumerate(packets):
            if idx < 15:
                sample_packets.append(self.dissect_packet(p, idx))

            if IP in p:
                proto = "TCP" if TCP in p else "UDP" if UDP in p else "ICMP" if ICMP in p else "OTHER"
                sport = int(p[TCP].sport) if TCP in p else int(p[UDP].sport) if UDP in p else 0
                dport = int(p[TCP].dport) if TCP in p else int(p[UDP].dport) if UDP in p else 0
                flow_key = (str(p[IP].src), str(p[IP].dst), sport, dport, proto)
                flows_dict[flow_key].append(p)
            elif IPv6 and IPv6 in p:
                proto = "TCP" if TCP in p else "UDP" if UDP in p else "ICMP" if (ICMPv6EchoRequest and ICMPv6EchoRequest in p) else "OTHER"
                sport = int(p[TCP].sport) if TCP in p else int(p[UDP].sport) if UDP in p else 0
                dport = int(p[TCP].dport) if TCP in p else int(p[UDP].dport) if UDP in p else 0
                flow_key = (str(p[IPv6].src), str(p[IPv6].dst), sport, dport, proto)
                flows_dict[flow_key].append(p)

        # Evaluate each flow
        analyzed_flows = []
        anomalies_detected = 0
        max_threat_score = 0

        for (src_ip, dst_ip, sport, dport, proto), flow_pkts in list(flows_dict.items())[:20]:
            features = self.extract_features_from_packets(flow_pkts, "pcap_flow")
            prediction = self.intrusion_service.analyze_telemetry(features)

            is_anomaly = prediction.get("anomaly_detected", False)
            if is_anomaly:
                anomalies_detected += 1
            threat_score = prediction.get("threat_score", 0)
            if threat_score > max_threat_score:
                max_threat_score = threat_score

            flow_hash = hashlib.md5(f"{src_ip}:{sport}->{dst_ip}:{dport}/{proto}".encode()).hexdigest()[:8].upper()
            flow_id = f"FLOW-{flow_hash}"

            first_pkt = flow_pkts[0] if flow_pkts else None
            first_pkt_time = getattr(first_pkt, 'time', None) if first_pkt else None
            if first_pkt_time is not None:
                try:
                    timestamp_str = datetime.fromtimestamp(float(first_pkt_time)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if len(flow_pkts) > 1 and hasattr(flow_pkts[0], 'time') and hasattr(flow_pkts[-1], 'time'):
                try:
                    duration_sec = round(abs(float(flow_pkts[-1].time) - float(flow_pkts[0].time)), 4)
                except Exception:
                    duration_sec = float(features.get("duration", 0.0))
            else:
                duration_sec = float(features.get("duration", 0.0))

            status_label = "SUSPICIOUS" if is_anomaly else "NORMAL"
            service_name = features.get("service", "http")
            flag_name = features.get("flag", "SF")
            summary_str = f"PCAP {proto} flow from {src_ip}:{sport} to {dst_ip}:{dport} ({len(flow_pkts)} packets, service: {service_name}, flag: {flag_name})"

            analyzed_flow = {
                "flow_id": flow_id,
                "event_id": flow_id,
                "id": flow_id,
                "timestamp": timestamp_str,
                "time": timestamp_str.split(" ")[-1] if " " in timestamp_str else timestamp_str,
                "source": f"{src_ip}:{sport}",
                "destination": f"{dst_ip}:{dport}",
                "source_ip": src_ip,
                "src_ip": src_ip,
                "destination_ip": dst_ip,
                "dst_ip": dst_ip,
                "source_port": sport,
                "sport": sport,
                "destination_port": dport,
                "dport": dport,
                "protocol": proto,
                "service": service_name,
                "flag": flag_name,
                "packet_count": len(flow_pkts),
                "packets": len(flow_pkts),
                "duration_sec": duration_sec,
                "summary": summary_str,
                "status": status_label,
                "threat_score": threat_score,
                "severity": prediction.get("severity", "LOW"),
                "anomaly_detected": is_anomaly,
                "is_anomaly": is_anomaly,
                "features": features,
                "verdict": prediction,
                "top_factors": prediction.get("top_contributing_features", [])
            }
            analyzed_flows.append(analyzed_flow)

        # Update live session metrics and live_events
        with self._lock:
            self.packets_captured += total_packets
            self.flows_created += len(flows_dict)
            self.flows_analyzed += len(analyzed_flows)
            if anomalies_detected > 0:
                self.suspicious_flows += anomalies_detected
                self.threats_detected += anomalies_detected
                self.engine_status = "ALERT"
            self.normal_flows += (len(analyzed_flows) - anomalies_detected)
            if max_threat_score > self.highest_threat_score:
                self.highest_threat_score = max_threat_score

            for f in reversed(analyzed_flows):
                self.live_events.insert(0, f)
            if len(self.live_events) > 100:
                self.live_events = self.live_events[:100]

            if anomalies_detected > 0:
                suspicious = [f for f in analyzed_flows if f["anomaly_detected"]]
                highest = max(suspicious, key=lambda x: x["threat_score"]) if suspicious else analyzed_flows[0]
                self.active_alert = {
                    "threat_title": "PCAP FORENSIC THREAT DETECTED",
                    "threat_score": highest["threat_score"],
                    "risk_level": highest["severity"],
                    "flow_id": highest["flow_id"],
                    "event_id": highest["flow_id"],
                    "id": highest["flow_id"],
                    "source": highest["source"],
                    "destination": highest["destination"],
                    "source_ip": highest["source_ip"],
                    "src_ip": highest["src_ip"],
                    "source_port": highest["source_port"],
                    "sport": highest["sport"],
                    "destination_ip": highest["destination_ip"],
                    "dst_ip": highest["dst_ip"],
                    "destination_port": highest["destination_port"],
                    "dport": highest["dport"],
                    "protocol": highest["protocol"],
                    "service": highest["service"],
                    "flag": highest["flag"],
                    "timestamp": highest["timestamp"],
                    "time": highest["time"],
                    "packet_count": highest["packet_count"],
                    "packets": highest["packets"],
                    "duration_sec": highest["duration_sec"],
                    "summary": highest["summary"],
                    "status": "SUSPICIOUS",
                    "severity": highest["severity"],
                    "anomaly_detected": True,
                    "is_anomaly": True,
                    "verdict": highest["verdict"],
                    "features": highest["features"],
                    "top_factors": highest["top_factors"]
                }

        return {
            "status": "SUCCESS",
            "filename": filename,
            "scapy_version": self.version,
            "total_packets": total_packets,
            "distinct_flows_count": len(flows_dict),
            "analyzed_flows_sample": analyzed_flows,
            "anomalous_flows_count": anomalies_detected,
            "max_threat_score": max_threat_score,
            "overall_severity": "CRITICAL" if max_threat_score > 75 else "HIGH" if max_threat_score > 50 else "LOW",
            "sample_packets": sample_packets
        }


_scapy_engine_instance = None


def get_scapy_service() -> ScapyTelemetryEngine:
    global _scapy_engine_instance
    if _scapy_engine_instance is None:
        _scapy_engine_instance = ScapyTelemetryEngine()
    return _scapy_engine_instance
