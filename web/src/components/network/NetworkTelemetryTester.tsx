import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  Zap, 
  Radio, 
  Play, 
  Square,
  RotateCcw,
  RefreshCw, 
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  Upload,
  FileUp,
  Download,
  Terminal,
  Server,
  Layers,
  CheckCircle2,
  ExternalLink,
  Eye,
  X
} from 'lucide-react';
import { API_BASE_URL } from '../../constants';

interface FeatureContribution {
  feature: string;
  importance: number;
  observed_value: any;
}

interface TelemetryResult {
  model_name: string;
  model_version: string;
  anomaly_detected: boolean;
  threat_score: number;
  raw_probability: number;
  severity: string;
  confidence: string;
  top_contributing_features: FeatureContribution[];
  attribution_boundary: string;
}

interface DissectedPacket {
  packet_id: number;
  summary: string;
  layers: string[];
  length_bytes: number;
  protocol: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  tcp_flags?: string;
  seq?: number;
  ack?: number;
  payload_sample?: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  timestamp?: string;
}

interface LiveEvent {
  event_id?: string;
  flow_id?: string;
  id?: string;
  timestamp?: string;
  time?: string;
  source?: string;
  destination?: string;
  source_ip?: string;
  src_ip?: string;
  destination_ip?: string;
  dst_ip?: string;
  source_port?: number;
  sport?: number;
  destination_port?: number;
  dport?: number;
  protocol: string;
  service?: string;
  flag?: string;
  packet_count?: number;
  packets?: number;
  duration_sec?: number;
  anomaly_detected?: boolean;
  is_anomaly?: boolean;
  threat_score: number;
  severity: string;
  status: 'NORMAL' | 'SUSPICIOUS';
  verdict?: TelemetryResult;
  features?: Record<string, any>;
  summary?: string;
  top_factors?: any[];
}

interface ScapyCraftResponse {
  scenario: string;
  scapy_engine: string;
  total_packets_crafted: number;
  sample_packets: DissectedPacket[];
  extracted_telemetry_features: Record<string, any>;
  model_verdict: TelemetryResult;
  incident?: LiveEvent;
}

interface PcapFlow {
  flow_id?: string;
  event_id?: string;
  id?: string;
  timestamp?: string;
  time?: string;
  source: string;
  destination: string;
  source_ip?: string;
  src_ip?: string;
  destination_ip?: string;
  dst_ip?: string;
  source_port?: number;
  sport?: number;
  destination_port?: number;
  dport?: number;
  protocol: string;
  packet_count: number;
  packets?: number;
  duration_sec?: number;
  summary?: string;
  threat_score: number;
  severity: string;
  anomaly_detected: boolean;
  is_anomaly?: boolean;
  status?: 'NORMAL' | 'SUSPICIOUS';
  flag?: string;
  service?: string;
  features?: Record<string, any>;
  verdict?: TelemetryResult;
  top_factors?: any[];
}

interface PcapResponse {
  status: string;
  filename: string;
  total_packets: number;
  distinct_flows_count: number;
  analyzed_flows_sample: PcapFlow[];
  anomalous_flows_count: number;
  max_threat_score: number;
  overall_severity: string;
  sample_packets: DissectedPacket[];
}

interface NetworkInterface {
  id: string;
  name: string;
  description: string;
  ip: string;
  is_active: boolean;
}

interface EngineStatus {
  status: 'STOPPED' | 'STARTING' | 'CAPTURING' | 'ANALYZING' | 'ALERT';
  scapy_version: string;
  has_libpcap: boolean;
  live_capture_available: boolean;
  capture_error: string | null;
  selected_interface: string | null;
  packets_captured: number;
  flows_created: number;
  flows_analyzed: number;
  normal_flows: number;
  suspicious_flows: number;
  threats_detected: number;
  highest_threat_score: number;
  current_risk_level: string;
  active_alert: any;
  supported_protocols: string[];
  pcap_parser: string;
}

export const NetworkTelemetryTester: React.FC<{ compact?: boolean }> = ({ compact = false }) => {
  const [activeTab, setActiveTab] = useState<'scapy'>('scapy');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Engine Control & Lifecycle State
  const [engineStatus, setEngineStatus] = useState<EngineStatus>({
    status: 'STOPPED',
    scapy_version: '2.7.0',
    has_libpcap: false,
    live_capture_available: false,
    capture_error: null,
    selected_interface: null,
    packets_captured: 0,
    flows_created: 0,
    flows_analyzed: 0,
    normal_flows: 0,
    suspicious_flows: 0,
    threats_detected: 0,
    highest_threat_score: 0,
    current_risk_level: 'LOW',
    active_alert: null,
    supported_protocols: ['TCP', 'UDP', 'ICMP', 'IP', 'Ethernet'],
    pcap_parser: 'Scapy Native Parser'
  });

  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('auto');
  const [driverMessage, setDriverMessage] = useState<string>('');
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [activeIncident, setActiveIncident] = useState<LiveEvent | null>(null);

  // Scapy Crafter State (Tab 1)
  const [scapyResult, setScapyResult] = useState<ScapyCraftResponse | null>(null);
  const [activeScenario, setActiveScenario] = useState<string>('syn_flood');

  // Simulation Lab & PCAP Export State (Tab 3)
  const [simScenario, setSimScenario] = useState<string>('syn_flood');
  const [simResult, setSimResult] = useState<ScapyCraftResponse | null>(null);
  const [exportedPcap, setExportedPcap] = useState<{
    filename: string;
    download_url: string;
    packet_count: number;
    file_size_bytes: number;
  } | null>(null);

  // Technical Accordion States
  const [showTechnicalPackets, setShowTechnicalPackets] = useState(false);
  const [showAll41Features, setShowAll41Features] = useState(false);
  const [showTechnicalExplanation, setShowTechnicalExplanation] = useState(false);

  // PCAP State (Tab 2)
  const [pcapResult, setPcapResult] = useState<PcapResponse | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [pcapSelectedFlow, setPcapSelectedFlow] = useState<PcapFlow | null>(null);

  // Manual What-If Slider State
  const [manualResult, setManualResult] = useState<TelemetryResult | null>(null);
  const [protocolType, setProtocolType] = useState('tcp');
  const [service, setService] = useState('http');
  const [flag, setFlag] = useState('SF');
  const [srcBytes, setSrcBytes] = useState(215);
  const [dstBytes, setDstBytes] = useState(3800);
  const [count, setCount] = useState(2);
  const [serrorRate, setSerrorRate] = useState(0.0);

  // Auto-fetch engine status & network interfaces on mount
  useEffect(() => {
    fetchEngineStatus();
    fetchInterfaces();
    runScapyCraft('syn_flood');
  }, []);

  // Polling interval when engine is running
  useEffect(() => {
    let interval: any = null;
    if (['STARTING', 'CAPTURING', 'ANALYZING', 'ALERT'].includes(engineStatus.status)) {
      interval = setInterval(() => {
        fetchEngineStatus();
        fetchLiveEvents();
      }, 1500);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [engineStatus.status]);

  const fetchEngineStatus = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/network/engine/status`);
      if (res.ok) {
        const data = await res.json();
        setEngineStatus(prev => ({
          ...prev,
          ...data,
          status: data.status || data.engine_status || prev.status,
          live_capture_available: Boolean(data.live_capture_available ?? data.driver_available ?? prev.live_capture_available),
          has_libpcap: Boolean(data.has_libpcap ?? data.driver_available ?? prev.has_libpcap),
          packets_captured: data.packets_captured ?? prev.packets_captured ?? 0,
          flows_created: data.flows_created ?? prev.flows_created ?? 0,
          flows_analyzed: data.flows_analyzed ?? prev.flows_analyzed ?? 0,
          normal_flows: data.normal_flows ?? prev.normal_flows ?? 0,
          suspicious_flows: data.suspicious_flows ?? prev.suspicious_flows ?? 0,
          threats_detected: data.threats_detected ?? prev.threats_detected ?? 0,
          highest_threat_score: data.highest_threat_score ?? prev.highest_threat_score ?? 0,
          current_risk_level: data.current_risk_level ?? prev.current_risk_level ?? 'LOW'
        }));
      }
    } catch (err) {
      console.error('Error fetching engine status:', err);
    }
  };

  const fetchInterfaces = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/network/interfaces`);
      if (res.ok) {
        const data = await res.json();
        setInterfaces(data.interfaces || []);
        setDriverMessage(data.driver_message || '');
        if (data.live_capture_available !== undefined) {
          setEngineStatus(prev => ({
            ...prev,
            live_capture_available: Boolean(data.live_capture_available),
            has_libpcap: Boolean(data.live_capture_available)
          }));
        }
      }
    } catch (err) {
      console.error('Error fetching interfaces:', err);
    }
  };

  const fetchLiveEvents = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/network/engine/events`);
      if (res.ok) {
        const data = await res.json();
        setLiveEvents(data.events || []);
      }
    } catch (err) {
      console.error('Error fetching events:', err);
    }
  };

  const handleStartEngine = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/network/engine/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: selectedInterface === 'auto' ? null : selectedInterface
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Failed to start engine.');
      }
      await fetchEngineStatus();
      await fetchLiveEvents();
    } catch (err: any) {
      setError(err.message || 'Error starting capture engine.');
    } finally {
      setLoading(false);
    }
  };

  const handleStopEngine = async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE_URL}/network/engine/stop`, { method: 'POST' });
      await fetchEngineStatus();
      await fetchLiveEvents();
    } catch (err: any) {
      setError('Error stopping engine.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetEngine = async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE_URL}/network/engine/reset`, { method: 'POST' });
      await fetchEngineStatus();
      setLiveEvents([]);
      setActiveIncident(null);
    } catch (err: any) {
      setError('Error resetting engine telemetry.');
    } finally {
      setLoading(false);
    }
  };

  const handleRunSafeDemoSimulation = async (scenario: string = 'syn_flood') => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/network/engine/simulate-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      if (!res.ok) throw new Error('Safe demo simulation failed.');
      const data = await res.json();
      setEngineStatus(data.session_metrics);
      fetchLiveEvents();
    } catch (err: any) {
      setError(err.message || 'Error running safe simulation.');
    } finally {
      setLoading(false);
    }
  };

  const runScapyCraft = async (scenario: string) => {
    setActiveScenario(scenario);
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/network/scapy/craft-test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      if (!res.ok) throw new Error('Traffic scenario test failed.');
      const data: ScapyCraftResponse = await res.json();
      setScapyResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to generate and analyze network traffic.');
    } finally {
      setLoading(false);
    }
  };

  const handleExportSimulationPcap = async (scenario: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/network/simulation/export-pcap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      if (!res.ok) throw new Error('Failed to export simulation PCAP.');
      const data = await res.json();
      setExportedPcap({
        filename: data.filename,
        download_url: data.download_url,
        packet_count: data.packet_count,
        file_size_bytes: data.file_size_bytes
      });
    } catch (err: any) {
      setError(err.message || 'Error exporting simulation PCAP.');
    } finally {
      setLoading(false);
    }
  };



  const handlePcapUpload = async (fileToUpload?: File) => {
    const targetFile = fileToUpload || selectedFile;
    if (!targetFile) return;

    setLoading(true);
    setError(null);
    const formData = new FormData();
    formData.append('file', targetFile);

    try {
      const res = await fetch(`${API_BASE_URL}/network/pcap/analyze`, {
        method: 'POST',
        body: formData
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || 'PCAP analysis failed.');
      }
      const data: PcapResponse = await res.json();
      setPcapResult(data);
    } catch (err: any) {
      setError(err.message || 'Error parsing PCAP file.');
    } finally {
      setLoading(false);
    }
  };

  const loadSamplePcap = async (filename: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/samples/${filename}`);
      if (!response.ok) throw new Error('Failed to load sample PCAP file.');
      const blob = await response.blob();
      const file = new File([blob], filename, { type: 'application/vnd.tcpdump.pcap' });
      setSelectedFile(file);
      await handlePcapUpload(file);
    } catch (err: any) {
      setError(err.message || 'Error loading sample PCAP.');
    } finally {
      setLoading(false);
    }
  };

  const runManualInference = async (payload: any) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/network/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error('What-If simulation failed.');
      const data: TelemetryResult = await res.json();
      setManualResult(data);
    } catch (err: any) {
      setError(err.message || 'Error analyzing telemetry.');
    } finally {
      setLoading(false);
    }
  };

  const getRiskLevelBadge = (score: number) => {
    if (score <= 30) {
      return {
        label: '🟢 LOW RISK',
        textColor: 'text-[#35C98A]',
        bgColor: 'bg-[#35C98A]/10',
        borderColor: 'border-[#35C98A]/30'
      };
    }
    if (score <= 60) {
      return {
        label: '🟡 MEDIUM RISK',
        textColor: 'text-[#F2B84B]',
        bgColor: 'bg-[#F2B84B]/10',
        borderColor: 'border-[#F2B84B]/30'
      };
    }
    if (score <= 80) {
      return {
        label: '🟠 HIGH RISK',
        textColor: 'text-[#F97316]',
        bgColor: 'bg-[#F97316]/10',
        borderColor: 'border-[#F97316]/30'
      };
    }
    return {
      label: '🔴 CRITICAL RISK',
      textColor: 'text-[#EF6262]',
      bgColor: 'bg-[#EF6262]/10',
      borderColor: 'border-[#EF6262]/30'
    };
  };

  const getPacketActivity = (pkt: DissectedPacket) => {
    if (pkt.protocol === 'ICMP') return 'Ping / Device Discovery Probe';
    if (pkt.protocol === 'TCP') {
      if (pkt.tcp_flags && pkt.tcp_flags.includes('S') && !pkt.tcp_flags.includes('A')) {
        return 'Connection Request (SYN)';
      }
      if (pkt.tcp_flags && pkt.tcp_flags.includes('A')) {
        return pkt.payload_sample ? 'Web Data Transfer (HTTP)' : 'Connection Acknowledgment (ACK)';
      }
      if (pkt.tcp_flags && (pkt.tcp_flags.includes('F') || pkt.tcp_flags.includes('R'))) {
        return 'Connection Close / Reset';
      }
      return 'TCP Network Packet';
    }
    return `${pkt.protocol} Packet`;
  };

  const getFeatureSummary = (features: Record<string, any>) => {
    const proto = (features.protocol_type || 'TCP').toUpperCase();
    let serviceName = 'General Service';
    const s = String(features.service || '').toLowerCase();
    if (s === 'http') serviceName = 'Web Service (HTTP)';
    else if (s === 'eco_i' || s === 'ecr_i') serviceName = 'Ping / Host Discovery';
    else if (s === 'smtp') serviceName = 'Email Service (SMTP)';
    else if (s === 'private') serviceName = 'Internal Network Service';
    else if (s) serviceName = s.toUpperCase();

    let connectionFailures = 'Normal';
    const serror = Number(features.serror_rate || 0);
    const flagVal = String(features.flag || '');
    if (serror >= 0.8 || flagVal === 'S0') connectionFailures = 'Very High';
    else if (serror > 0.2) connectionFailures = 'Elevated';

    let dataSent = 'None (0 bytes)';
    const src = Number(features.src_bytes || 0);
    if (src > 1000) dataSent = `${(src / 1024).toFixed(1)} KB`;
    else if (src > 0) dataSent = `${src} bytes`;

    let dataReceived = 'None (0 bytes)';
    const dst = Number(features.dst_bytes || 0);
    if (dst > 1000) dataReceived = `${(dst / 1024).toFixed(1)} KB`;
    else if (dst > 0) dataReceived = `${dst} bytes`;

    let repeatedAttempts = 'Normal';
    const cnt = Number(features.count || 0);
    if (cnt >= 20) repeatedAttempts = 'Very High';
    else if (cnt >= 5) repeatedAttempts = 'Moderate';

    return { proto, serviceName, connectionFailures, dataSent, dataReceived, repeatedAttempts };
  };

  const getFriendlyExplanation = (feat: FeatureContribution, isAnomaly: boolean) => {
    const name = feat.feature.toLowerCase();
    const val = feat.observed_value;
    if (name.includes('count') || name.includes('dst_host_count')) {
      return isAnomaly ? '🔴 Too many connection attempts' : '🟢 Connection frequency is normal';
    }
    if (name.includes('serror') || name === 'flag') {
      return isAnomaly ? '🔴 Connections are not completing' : '🟢 Connections are completing normally';
    }
    if (name.includes('diff_srv') || name.includes('dst_host_diff')) {
      return isAnomaly ? '🟠 Multiple different network ports probed' : '🟢 Port access pattern is consistent';
    }
    if (name.includes('same_srv')) {
      return isAnomaly ? '🟠 Repeated activity detected on same target' : '🟢 Target distribution is normal';
    }
    if (name.includes('src_bytes')) {
      return val === 0 || val === '0'
        ? '🟡 Zero data sent in connection request'
        : `Data transmission pattern (${val} bytes)`;
    }
    if (name.includes('dst_bytes')) {
      return val === 0 || val === '0'
        ? '🟡 Zero response data received'
        : `Response data volume (${val} bytes)`;
    }
    if (name.includes('service')) {
      return isAnomaly ? `🟠 Unusual traffic pattern on ${val}` : `🟢 Normal service interaction (${val})`;
    }
    return isAnomaly ? `🟠 Unusual traffic pattern (${feat.feature})` : `🟢 Standard network behavior (${feat.feature})`;
  };

  const getStatusBadge = (status: EngineStatus['status']) => {
    switch (status) {
      case 'CAPTURING':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-[#35C98A]/15 text-[#35C98A] border border-[#35C98A]/40">
            <span className="w-2 h-2 rounded-full bg-[#35C98A] animate-ping" />
            <span>🟢 CAPTURING</span>
          </span>
        );
      case 'ANALYZING':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-[#5B8DEF]/15 text-[#5B8DEF] border border-[#5B8DEF]/40">
            <span className="w-2 h-2 rounded-full bg-[#5B8DEF] animate-pulse" />
            <span>🔵 ANALYZING</span>
          </span>
        );
      case 'ALERT':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-[#EF6262]/20 text-[#EF6262] border border-[#EF6262]/50 animate-bounce">
            <span className="w-2 h-2 rounded-full bg-[#EF6262]" />
            <span>🚨 ALERT TRIGGERED</span>
          </span>
        );
      case 'STARTING':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-[#F2B84B]/15 text-[#F2B84B] border border-[#F2B84B]/40">
            <span className="w-2 h-2 rounded-full bg-[#F2B84B] animate-spin" />
            <span>🟡 STARTING</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-[#25313E] text-[#8996A6] border border-[#3B4D61]">
            <span className="w-2 h-2 rounded-full bg-[#64748B]" />
            <span>⏹ STOPPED</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* ========================================================================= */}
      {/* 1. ENGINE 5 CONTROL PANEL & STATUS HEADER */}
      {/* ========================================================================= */}
      <div className="rounded-xl bg-[#0F151D] border border-[#25313E] overflow-hidden shadow-xl">
        <div className="p-4 sm:p-5 border-b border-[#25313E] bg-gradient-to-r from-[#121A24] via-[#0E151E] to-[#121A24] flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-lg bg-[#5B8DEF]/15 border border-[#5B8DEF]/30 flex items-center justify-center text-[#5B8DEF] shadow-inner">
              <Radio size={22} className={engineStatus.status === 'CAPTURING' ? 'animate-pulse' : ''} />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-base font-bold text-[#E8EDF3] tracking-wide">
                  ENGINE 5 — NETWORK THREAT DETECTOR
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#5B8DEF]/15 text-[#5B8DEF] border border-[#5B8DEF]/30">
                  Scapy v{engineStatus.scapy_version}
                </span>
              </div>
              <p className="text-xs text-[#8996A6] mt-0.5">
                Passive packet capture, flow aggregation, 41-feature KDD extraction & Random Forest intrusion scoring
              </p>
            </div>
          </div>

          {/* Engine Status Badge & Buttons */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 bg-[#0A0E15] px-3 py-1.5 rounded-lg border border-[#25313E]">
              <span className="text-[11px] font-bold text-[#8996A6] uppercase tracking-wider mr-1">
                ENGINE STATUS:
              </span>
              {getStatusBadge(engineStatus.status)}
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-2">
              {engineStatus.status === 'STOPPED' ? (
                <button
                  onClick={handleStartEngine}
                  disabled={loading}
                  className="px-4 py-2 rounded-lg bg-[#35C98A] hover:bg-[#2EB37A] text-[#0A0E15] font-bold text-xs flex items-center gap-1.5 transition-all shadow-md cursor-pointer disabled:opacity-50"
                >
                  <Play size={14} fill="currentColor" />
                  <span>START ENGINE</span>
                </button>
              ) : (
                <button
                  onClick={handleStopEngine}
                  disabled={loading}
                  className="px-4 py-2 rounded-lg bg-[#EF6262] hover:bg-[#D95353] text-white font-bold text-xs flex items-center gap-1.5 transition-all shadow-md cursor-pointer disabled:opacity-50"
                >
                  <Square size={14} fill="currentColor" />
                  <span>STOP ENGINE</span>
                </button>
              )}

              <button
                onClick={handleResetEngine}
                disabled={loading}
                title="Reset session counters and live events without deleting historical logs"
                className="px-3.5 py-2 rounded-lg bg-[#1F2937] hover:bg-[#2A374A] text-[#E8EDF3] border border-[#3B4D61] font-semibold text-xs flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-50"
              >
                <RotateCcw size={14} />
                <span>RESET</span>
              </button>
            </div>
          </div>
        </div>

        {/* Interface Selector & Npcap Driver Availability Bar */}
        <div className="p-3.5 sm:px-5 bg-[#0A0E15] border-b border-[#25313E] flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-[#8996A6] font-medium flex items-center gap-1.5">
              <Server size={14} className="text-[#5B8DEF]" />
              Network Interface:
            </span>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={engineStatus.status !== 'STOPPED'}
              className="bg-[#151D27] border border-[#25313E] text-[#E8EDF3] rounded-md px-3 py-1.5 text-xs focus:border-[#5B8DEF] focus:outline-none max-w-[280px] truncate"
            >
              <option value="auto">Auto Detect (Default Active)</option>
              {interfaces.map((iface) => (
                <option key={iface.id} value={iface.id}>
                  {iface.name} {iface.ip ? `(${iface.ip})` : ''} - {iface.description}
                </option>
              ))}
            </select>
            <button
              onClick={fetchInterfaces}
              className="text-[#8996A6] hover:text-[#E8EDF3] p-1.5 rounded hover:bg-[#1E293B] transition-colors"
              title="Refresh network interfaces"
            >
              <RefreshCw size={13} />
            </button>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-[#8996A6] font-medium">Capture Driver:</span>
              {engineStatus.live_capture_available ? (
                <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-[#35C98A]/15 text-[#35C98A] border border-[#35C98A]/30">
                  🟢 AVAILABLE (Npcap/libpcap)
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-[#EF6262]/15 text-[#EF6262] border border-[#EF6262]/30">
                  🔴 UNAVAILABLE (No Npcap Driver)
                </span>
              )}
            </div>

            {!engineStatus.live_capture_available && (
              <button
                onClick={() => handleRunSafeDemoSimulation('syn_flood')}
                disabled={loading}
                className="px-2.5 py-1 rounded bg-[#5B8DEF]/15 hover:bg-[#5B8DEF]/25 text-[#5B8DEF] border border-[#5B8DEF]/30 text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Runs an in-memory Scapy attack simulation that feeds live engine telemetry safely"
              >
                <Zap size={12} />
                <span>Run Safe Simulation</span>
              </button>
            )}
          </div>
        </div>

        {/* Warning banner when live capture is unavailable */}
        {!engineStatus.live_capture_available && (
          <div className="px-4 py-2.5 bg-[#EF6262]/10 border-b border-[#EF6262]/25 text-xs text-[#EF6262] flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <AlertTriangle size={15} className="shrink-0" />
              <span>
                <strong>Live capture unavailable on this system:</strong> Live capture requires a supported packet-capture driver such as Npcap and administrator privileges.
                Use <strong>PCAP upload</strong> or <strong>What-If Simulation</strong> instead.
              </span>
            </div>
            <button
              onClick={() => handleRunSafeDemoSimulation('syn_flood')}
              className="underline hover:text-white font-bold shrink-0 ml-2 cursor-pointer"
            >
              Demo Simulation &rarr;
            </button>
          </div>
        )}

        {/* Live Counters & Metrics Strip */}
        <div className="p-4 bg-[#080C12] grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Packets Captured</span>
            <span className="text-lg font-mono font-bold text-[#E8EDF3]">
              {(engineStatus.packets_captured ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Flows Created</span>
            <span className="text-lg font-mono font-bold text-[#5B8DEF]">
              {(engineStatus.flows_created ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Flows Analyzed</span>
            <span className="text-lg font-mono font-bold text-[#E8EDF3]">
              {(engineStatus.flows_analyzed ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Normal Flows</span>
            <span className="text-lg font-mono font-bold text-[#35C98A]">
              {(engineStatus.normal_flows ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Suspicious Flows</span>
            <span className="text-lg font-mono font-bold text-[#F97316]">
              {(engineStatus.suspicious_flows ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Threats Detected</span>
            <span className="text-lg font-mono font-bold text-[#EF6262]">
              {(engineStatus.threats_detected ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Highest Score</span>
            <span className={`text-lg font-mono font-bold ${(engineStatus.highest_threat_score ?? 0) > 60 ? 'text-[#EF6262]' : 'text-[#35C98A]'}`}>
              {engineStatus.highest_threat_score ?? 0}/100
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
            <span className="text-[10px] uppercase font-bold text-[#8996A6] block">Current Risk</span>
            <span className="text-xs font-bold font-mono block mt-1">
              <span className={`px-2 py-0.5 rounded border inline-block ${getRiskLevelBadge(engineStatus.highest_threat_score ?? 0).bgColor} ${getRiskLevelBadge(engineStatus.highest_threat_score ?? 0).textColor} ${getRiskLevelBadge(engineStatus.highest_threat_score ?? 0).borderColor}`}>
                {engineStatus.current_risk_level || 'LOW'}
              </span>
            </span>
          </div>
        </div>

        {/* Real-time Alert Banner */}
        {engineStatus.active_alert && (
          <div className="p-4 bg-[#EF6262]/15 border-t border-[#EF6262]/40 text-[#EF6262] flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-full bg-[#EF6262]/25 flex items-center justify-center text-[#EF6262] shrink-0">
                <ShieldAlert size={20} className="animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-black tracking-wider uppercase bg-[#EF6262] text-[#0A0E15] px-2 py-0.5 rounded">
                    🚨 SECURITY ALERT
                  </span>
                  <span className="text-xs font-bold text-white">
                    {engineStatus.active_alert.threat_title}
                  </span>
                </div>
                <div className="text-xs text-[#E8EDF3] mt-1 flex flex-wrap gap-x-4 gap-y-1">
                  <span><strong>Source:</strong> <span className="font-mono text-[#EF6262]">{engineStatus.active_alert.source_ip}</span></span>
                  <span><strong>Target:</strong> <span className="font-mono text-[#5B8DEF]">{engineStatus.active_alert.destination_ip}</span></span>
                  <span><strong>Protocol:</strong> <span className="font-mono">{engineStatus.active_alert.protocol}</span></span>
                  <span><strong>Threat Score:</strong> <span className="font-mono font-bold text-[#EF6262]">{engineStatus.active_alert.threat_score}/100</span></span>
                  <span><strong>Severity:</strong> <span className="font-bold">{engineStatus.active_alert.risk_level}</span></span>
                </div>
              </div>
            </div>

            {liveEvents.length > 0 && (
              <button
                onClick={() => setActiveIncident(liveEvents[0])}
                className="px-3.5 py-1.5 rounded-lg bg-[#EF6262] hover:bg-[#D95353] text-white text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Eye size={14} />
                <span>View Forensic Details</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* 2. TOP NAVIGATION TABS */}
      {/* ========================================================================= */}
      <div className="rounded-xl bg-[#0F151D] border border-[#25313E] overflow-hidden shadow-lg">
        <div className="flex border-b border-[#25313E] bg-[#0A0E15] px-4 sm:px-6 gap-2 pt-2">
          <button
            onClick={() => setActiveTab('scapy')}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'scapy'
                ? 'border-[#5B8DEF] text-[#5B8DEF] bg-[#5B8DEF]/5'
                : 'border-transparent text-[#8996A6] hover:text-[#E8EDF3]'
            }`}
          >
            <span>🔍 Test Network Traffic</span>
          </button>

        </div>

        {/* Error Notification */}
        {error && (
          <div className="m-4 p-4 rounded-lg bg-[#EF6262]/10 border border-[#EF6262]/30 text-xs text-[#EF6262] flex items-center gap-2">
            <AlertTriangle size={16} />
            <span>{error}</span>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 1: TEST NETWORK TRAFFIC */}
        {/* ========================================================================= */}
        {activeTab === 'scapy' && (
          <div className="p-4 sm:p-6 space-y-6">
            {/* Live Activity Table if Engine has captured flows */}
            {liveEvents.length > 0 && (
              <div className="rounded-xl bg-[#080C12] border border-[#25313E] overflow-hidden">
                <div className="p-3.5 bg-[#121A24] border-b border-[#25313E] flex items-center justify-between">
                  <div className="flex items-center gap-2 text-[#5B8DEF] font-bold text-xs sm:text-sm">
                    <Activity size={16} />
                    <span>Live Network Activity Stream</span>
                    <span className="text-xs font-normal text-[#8996A6]">
                      ({liveEvents.length} flows observed)
                    </span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-[#1F2937] text-[#93C5FD]">
                    Real-time Pipeline
                  </span>
                </div>
                <div className="overflow-x-auto max-h-[300px]">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-[#0D131C] text-[#8996A6] text-[10px] uppercase border-b border-[#25313E] sticky top-0">
                      <tr>
                        <th className="p-2.5">Time</th>
                        <th className="p-2.5">Source IP</th>
                        <th className="p-2.5">Destination IP</th>
                        <th className="p-2.5">Protocol / Port</th>
                        <th className="p-2.5">Status</th>
                        <th className="p-2.5">Threat Score</th>
                        <th className="p-2.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#25313E]/40 text-[11px]">
                      {liveEvents.map((evt, idx) => {
                        const flowKey = `${evt.flow_id || evt.event_id || evt.id || 'evt'}-${idx}`;
                        const displayTime = evt.timestamp || evt.time || 'N/A';
                        const srcHost = evt.source_ip || evt.src_ip || (evt.source ? evt.source.split(':')[0] : 'Unknown');
                        const srcPort = evt.source_port !== undefined ? evt.source_port : (evt.sport !== undefined ? evt.sport : (evt.source && evt.source.includes(':') ? evt.source.split(':')[1] : ''));
                        const dstHost = evt.destination_ip || evt.dst_ip || (evt.destination ? evt.destination.split(':')[0] : 'Unknown');
                        const dstPort = evt.destination_port !== undefined ? evt.destination_port : (evt.dport !== undefined ? evt.dport : (evt.destination && evt.destination.includes(':') ? evt.destination.split(':')[1] : ''));
                        const serviceName = evt.service || (evt.features && evt.features['service']) || 'other';

                        return (
                          <tr key={flowKey} className="hover:bg-[#121A24]/60 transition-colors">
                            <td className="p-2.5 font-mono text-[#8996A6]">{displayTime}</td>
                            <td className="p-2.5 font-mono text-[#E8EDF3] font-medium">{srcHost}{srcPort ? `:${srcPort}` : ''}</td>
                            <td className="p-2.5 font-mono text-[#5B8DEF]">{dstHost}{dstPort ? `:${dstPort}` : ''}</td>
                            <td className="p-2.5 font-mono text-[#8996A6]">{evt.protocol} ({serviceName})</td>
                            <td className="p-2.5">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                evt.status === 'SUSPICIOUS' || evt.threat_score > 50 ? 'bg-[#EF6262]/20 text-[#EF6262]' : 'bg-[#35C98A]/20 text-[#35C98A]'
                              }`}>
                                {evt.status === 'SUSPICIOUS' || evt.threat_score > 50 ? 'SUSPICIOUS FLOW' : 'NORMAL'}
                              </span>
                            </td>
                            <td className="p-2.5 font-bold font-mono">
                              <span className={evt.threat_score > 60 ? 'text-[#EF6262]' : 'text-[#35C98A]'}>
                                {evt.threat_score} / 100
                              </span>
                            </td>
                            <td className="p-2.5 text-right">
                              <button
                                onClick={() => setActiveIncident(evt)}
                                className="px-2.5 py-1 rounded bg-[#1F2937] hover:bg-[#2A374A] text-[#93C5FD] hover:text-white border border-[#3B4D61] text-[10px] font-semibold transition-colors cursor-pointer"
                              >
                                View Details
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Scenario Selection Grid */}
            <div>
              <label className="text-xs font-bold tracking-wider uppercase text-[#8996A6] block mb-2.5">
                SELECT A TRAFFIC SCENARIO TO TEST
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <button
                  onClick={() => runScapyCraft('syn_flood')}
                  disabled={loading}
                  className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
                    activeScenario === 'syn_flood'
                      ? 'bg-[#EF6262]/10 border-[#EF6262] text-[#EF6262]'
                      : 'bg-[#151D27] border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold">🔴 SYN Flood Attack</span>
                  </div>
                  <p className="text-[11px] opacity-85 leading-relaxed">
                    Simulates repeated connection attempts toward a target.
                  </p>
                </button>

                <button
                  onClick={() => runScapyCraft('port_scan')}
                  disabled={loading}
                  className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
                    activeScenario === 'port_scan'
                      ? 'bg-[#F2B84B]/10 border-[#F2B84B] text-[#F2B84B]'
                      : 'bg-[#151D27] border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold">🟠 Port Scanning</span>
                  </div>
                  <p className="text-[11px] opacity-85 leading-relaxed">
                    Simulates an attacker checking different network ports.
                  </p>
                </button>

                <button
                  onClick={() => runScapyCraft('icmp_sweep')}
                  disabled={loading}
                  className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
                    activeScenario === 'icmp_sweep'
                      ? 'bg-[#5B8DEF]/10 border-[#5B8DEF] text-[#5B8DEF]'
                      : 'bg-[#151D27] border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold">🟡 Network Scanning</span>
                  </div>
                  <p className="text-[11px] opacity-85 leading-relaxed">
                    Simulates an attacker discovering devices on the network.
                  </p>
                </button>

                <button
                  onClick={() => runScapyCraft('benign_http')}
                  disabled={loading}
                  className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
                    activeScenario === 'benign_http'
                      ? 'bg-[#35C98A]/10 border-[#35C98A] text-[#35C98A]'
                      : 'bg-[#151D27] border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold">🟢 Normal Web Activity</span>
                  </div>
                  <p className="text-[11px] opacity-85 leading-relaxed">
                    Simulates normal website access by a user.
                  </p>
                </button>
              </div>
            </div>

            {/* Results Grid */}
            {scapyResult && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* Left Panel: Observed Packets */}
                <div className="rounded-xl bg-[#080C12] border border-[#25313E] overflow-hidden flex flex-col">
                  <div className="p-3.5 bg-[#121A24] border-b border-[#25313E] flex items-center justify-between">
                    <div className="flex items-center gap-2 text-[#5B8DEF] font-bold text-xs sm:text-sm">
                      <span>📡 Network Activity Observed</span>
                      <span className="text-xs font-normal text-[#8996A6]">
                        ({scapyResult.total_packets_crafted} packets)
                      </span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-[#1F2937] text-[#93C5FD]">
                      Dissection Stream
                    </span>
                  </div>

                  <div className="p-3.5 space-y-2.5 max-h-[380px] overflow-y-auto">
                    {scapyResult.sample_packets.map((pkt) => {
                      const activity = getPacketActivity(pkt);
                      const isSuspicious = scapyResult.model_verdict.anomaly_detected;

                      return (
                        <div
                          key={pkt.packet_id}
                          className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E] hover:border-[#3B4D61] transition-all text-xs"
                        >
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="font-semibold text-[#E8EDF3] text-[11px]">
                              Packet #{pkt.packet_id} [{pkt.protocol}]
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                isSuspicious
                                  ? 'bg-[#EF6262]/15 text-[#EF6262] border border-[#EF6262]/30'
                                  : 'bg-[#35C98A]/15 text-[#35C98A] border border-[#35C98A]/30'
                              }`}
                            >
                              {isSuspicious ? 'Suspicious Flow' : 'Normal Flow'}
                            </span>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[11px] text-[#8996A6]">
                            <div>
                              <span className="text-[#64748B] block text-[10px]">Source</span>
                              <span className="font-mono text-[#E8EDF3]">
                                {pkt.src_ip || '10.0.0.1'}:{pkt.src_port || '0'}
                              </span>
                            </div>
                            <div>
                              <span className="text-[#64748B] block text-[10px]">Destination</span>
                              <span className="font-mono text-[#E8EDF3]">
                                {pkt.dst_ip || '192.168.1.1'}:{pkt.dst_port || '80'}
                              </span>
                            </div>
                          </div>

                          <div className="mt-2 pt-1.5 border-t border-[#25313E]/50 flex items-center justify-between text-[11px]">
                            <span className="text-[#8996A6]">Dissection:</span>
                            <span className="font-medium text-[#5B8DEF]">{activity}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Expandable Technical Packet Details */}
                  <div className="border-t border-[#25313E] bg-[#0A0E15]">
                    <button
                      onClick={() => setShowTechnicalPackets(!showTechnicalPackets)}
                      className="w-full p-2.5 px-3.5 flex items-center justify-between text-xs text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#121A24] transition-colors cursor-pointer"
                    >
                      <span className="flex items-center gap-2 font-medium">
                        <Terminal size={13} />
                        View Technical Packet Dissection
                      </span>
                      {showTechnicalPackets ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>

                    {showTechnicalPackets && (
                      <div className="p-3 bg-[#05080C] border-t border-[#25313E] max-h-[220px] overflow-y-auto font-mono text-[10px] space-y-2 divide-y divide-[#25313E]/40 text-[#8996A6]">
                        {scapyResult.sample_packets.map((pkt) => (
                          <div key={pkt.packet_id} className="pt-1.5 first:pt-0">
                            <div className="flex items-center justify-between text-[#5B8DEF] font-bold">
                              <span>#{pkt.packet_id} [{pkt.protocol}] - {pkt.length_bytes} bytes</span>
                              {pkt.tcp_flags && <span className="text-[#FDE047]">Flags: {pkt.tcp_flags}</span>}
                            </div>
                            <div className="text-[#E8EDF3] break-all my-0.5">{pkt.summary}</div>
                            <div className="text-[10px] text-[#64748B]">
                              Layers: {pkt.layers.join(' → ')} | {pkt.src_ip}:{pkt.src_port || 0} → {pkt.dst_ip}:{pkt.dst_port || 0}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Right Side: Verdict, Observations & Explanations */}
                <div className="space-y-4">
                  {/* Result Verdict Card */}
                  {(() => {
                    const isAnomaly = scapyResult.model_verdict.anomaly_detected;
                    const score = scapyResult.model_verdict.threat_score;
                    const riskBadge = getRiskLevelBadge(score);

                    return (
                      <div
                        className={`p-4 rounded-xl border transition-all ${
                          isAnomaly
                            ? 'bg-[#EF6262]/10 border-[#EF6262]/40 text-[#EF6262]'
                            : 'bg-[#35C98A]/10 border-[#35C98A]/40 text-[#35C98A]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div
                              className={`w-11 h-11 rounded-full flex items-center justify-center shrink-0 ${
                                isAnomaly ? 'bg-[#EF6262]/20' : 'bg-[#35C98A]/20'
                              }`}
                            >
                              {isAnomaly ? <ShieldAlert size={24} /> : <ShieldCheck size={24} />}
                            </div>
                            <div>
                              <h3 className="text-sm sm:text-base font-bold tracking-wide uppercase">
                                {isAnomaly ? 'SUSPICIOUS FLOW DETECTED' : 'NORMAL FLOW DETECTED'}
                              </h3>
                              <p className="text-xs opacity-90 mt-0.5">
                                {isAnomaly
                                  ? 'Engine 5 Random Forest flagged abnormal connection behavior.'
                                  : 'Flow features adhere to standard benign transport profile.'}
                              </p>
                            </div>
                          </div>

                          <div className="text-right bg-[#080C12]/80 px-3.5 py-2 rounded-lg border border-[#25313E] shrink-0">
                            <span className="text-[10px] uppercase text-[#8996A6] block font-medium">
                              Threat Score
                            </span>
                            <span
                              className={`text-2xl font-bold font-mono ${
                                score > 60 ? 'text-[#EF6262]' : 'text-[#35C98A]'
                              }`}
                            >
                              {score} <span className="text-xs text-[#8996A6]">/ 100</span>
                            </span>
                            <div className="mt-1">
                              <span
                                className={`text-[10px] font-bold px-2 py-0.5 rounded border inline-block ${riskBadge.bgColor} ${riskBadge.textColor} ${riskBadge.borderColor}`}
                              >
                                {riskBadge.label}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })()}

                  {scapyResult.incident && (
                    <div className="flex justify-end">
                      <button
                        onClick={() => setActiveIncident(scapyResult.incident!)}
                        className="px-3.5 py-2 rounded-lg bg-[#EF6262] hover:bg-[#D95353] text-white text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer shadow-lg"
                      >
                        <Eye size={14} />
                        <span>View Forensic Incident Details</span>
                      </button>
                    </div>
                  )}

                  {/* Observations Section */}
                  {(() => {
                    const obs = getFeatureSummary(scapyResult.extracted_telemetry_features);

                    return (
                      <div className="p-4 rounded-xl bg-[#080C12] border border-[#25313E] space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[#E8EDF3] text-xs sm:text-sm flex items-center gap-1.5">
                            <Activity size={14} className="text-[#5B8DEF]" />
                            <span>📊 What Did Engine 5 Observe?</span>
                          </span>
                          <span className="text-[11px] text-[#8996A6]">KDD Flow Features</span>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
                          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
                            <span className="text-[#8996A6] block text-[10px] mb-0.5">Protocol</span>
                            <span className="text-[#E8EDF3] font-semibold">{obs.proto}</span>
                          </div>

                          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
                            <span className="text-[#8996A6] block text-[10px] mb-0.5">Service</span>
                            <span className="text-[#E8EDF3] font-semibold truncate block">{obs.serviceName}</span>
                          </div>

                          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
                            <span className="text-[#8996A6] block text-[10px] mb-0.5">Connection Failures</span>
                            <span
                              className={`font-semibold ${
                                obs.connectionFailures === 'Very High' ? 'text-[#EF6262]' : 'text-[#35C98A]'
                              }`}
                            >
                              {obs.connectionFailures}
                            </span>
                          </div>

                          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
                            <span className="text-[#8996A6] block text-[10px] mb-0.5">Data Sent</span>
                            <span className="text-[#E8EDF3] font-semibold">{obs.dataSent}</span>
                          </div>

                          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
                            <span className="text-[#8996A6] block text-[10px] mb-0.5">Data Received</span>
                            <span className="text-[#E8EDF3] font-semibold">{obs.dataReceived}</span>
                          </div>

                          <div className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E]">
                            <span className="text-[#8996A6] block text-[10px] mb-0.5">Repeated Attempts</span>
                            <span
                              className={`font-semibold ${
                                obs.repeatedAttempts === 'Very High' ? 'text-[#EF6262]' : 'text-[#E8EDF3]'
                              }`}
                            >
                              {obs.repeatedAttempts}
                            </span>
                          </div>
                        </div>

                        {/* Expandable 41 Features */}
                        <div className="pt-1">
                          <button
                            onClick={() => setShowAll41Features(!showAll41Features)}
                            className="text-xs text-[#5B8DEF] hover:text-[#93C5FD] flex items-center gap-1 font-medium transition-colors cursor-pointer"
                          >
                            <span>{showAll41Features ? 'Hide' : 'View'} 41 Technical Features</span>
                            {showAll41Features ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                          </button>

                          {showAll41Features && (
                            <div className="mt-2.5 p-3 rounded-lg bg-[#05080C] border border-[#25313E] max-h-[220px] overflow-y-auto font-mono text-[10px] grid grid-cols-2 sm:grid-cols-3 gap-2 text-[#8996A6]">
                              {Object.entries(scapyResult.extracted_telemetry_features).map(([key, val]) => (
                                <div key={key} className="p-1.5 rounded bg-[#121A24]/60 border border-[#25313E]/50">
                                  <span className="text-[#64748B] block truncate">{key}</span>
                                  <span className="text-[#E8EDF3] font-bold">{String(val)}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })()}

                  {/* Why Flagged Explanation Section */}
                  {scapyResult.model_verdict.top_contributing_features && (
                    <div className="p-4 rounded-xl bg-[#080C12] border border-[#25313E] space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-[#E8EDF3] text-xs sm:text-sm flex items-center gap-1.5">
                          <Zap size={14} className="text-[#F2B84B]" />
                          <span>💡 Why Was This Flagged?</span>
                        </span>
                        <span className="text-[11px] text-[#8996A6]">Random Forest Gini Importance</span>
                      </div>

                      <div className="space-y-2">
                        {scapyResult.model_verdict.top_contributing_features.slice(0, 4).map((feat, idx) => {
                          const friendlyText = getFriendlyExplanation(
                            feat,
                            scapyResult.model_verdict.anomaly_detected
                          );

                          return (
                            <div
                              key={idx}
                              className="p-2.5 rounded-lg bg-[#121A24] border border-[#25313E] flex items-center justify-between text-xs"
                            >
                              <span className="font-medium text-[#E8EDF3]">{friendlyText}</span>
                              <span className="text-[11px] font-mono text-[#8996A6] shrink-0">
                                {(feat.importance * 100).toFixed(1)}% impact
                              </span>
                            </div>
                          );
                        })}
                      </div>

                      <div className="pt-1">
                        <button
                          onClick={() => setShowTechnicalExplanation(!showTechnicalExplanation)}
                          className="text-xs text-[#5B8DEF] hover:text-[#93C5FD] flex items-center gap-1 font-medium transition-colors cursor-pointer"
                        >
                          <span>{showTechnicalExplanation ? 'Hide' : 'View'} Gini Mathematical Breakdown</span>
                          {showTechnicalExplanation ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                        </button>

                        {showTechnicalExplanation && (
                          <div className="mt-2.5 p-3 rounded-lg bg-[#05080C] border border-[#25313E] space-y-2 font-mono text-[10px]">
                            {scapyResult.model_verdict.top_contributing_features.map((feat, idx) => (
                              <div key={idx} className="flex items-center justify-between gap-2 text-[#8996A6]">
                                <span className="text-[#E8EDF3] w-36 truncate">
                                  {feat.feature} ({String(feat.observed_value)})
                                </span>
                                <div className="flex-1 h-1.5 rounded-full bg-[#1F2937] overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${
                                      scapyResult.model_verdict.anomaly_detected ? 'bg-[#EF6262]' : 'bg-[#35C98A]'
                                    }`}
                                    style={{ width: `${Math.min(100, Math.round(feat.importance * 350))}%` }}
                                  />
                                </div>
                                <span className="text-right w-12 text-[#93C5FD]">
                                  {(feat.importance * 100).toFixed(1)}%
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2 (PCAP) & TAB 3 (What-If) removed — not relevant to SIH26106 email threat detection scope */}
      </div>

      {/* ========================================================================= */}
      {/* 8. INCIDENT DETAILS MODAL / EXPANDABLE INSPECTOR */}
      {/* ========================================================================= */}
      {activeIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#0F151D] border border-[#25313E] rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto shadow-2xl">
            {/* Modal Header */}
            <div className="p-5 border-b border-[#25313E] bg-[#121A24] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                  activeIncident.status === 'SUSPICIOUS' ? 'bg-[#EF6262]/20 text-[#EF6262]' : 'bg-[#35C98A]/20 text-[#35C98A]'
                }`}>
                  <ShieldAlert size={22} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white tracking-wide">
                    INCIDENT DETAILS & FORENSIC EVIDENCE
                  </h3>
                  <span className="text-xs text-[#8996A6]">
                    Flow ID: {activeIncident.flow_id || activeIncident.event_id || activeIncident.id || 'N/A'} | Timestamp: {activeIncident.timestamp || activeIncident.time || 'N/A'}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setActiveIncident(null)}
                className="p-1.5 rounded-lg bg-[#1F2937] hover:bg-[#2A374A] text-[#8996A6] hover:text-white transition-colors"
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* THREAT OVERVIEW */}
              <div className="p-4 rounded-xl bg-[#080C12] border border-[#25313E] grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div>
                  <span className="text-[#8996A6] block text-[10px] uppercase font-semibold">Source Host</span>
                  <span className="font-mono text-[#EF6262] font-bold text-sm block">
                    {activeIncident.source_ip || activeIncident.src_ip || (activeIncident.source ? activeIncident.source.split(':')[0] : 'Unknown')}
                    :
                    {activeIncident.source_port !== undefined ? activeIncident.source_port : (activeIncident.sport !== undefined ? activeIncident.sport : (activeIncident.source && activeIncident.source.includes(':') ? activeIncident.source.split(':')[1] : '0'))}
                  </span>
                </div>
                <div>
                  <span className="text-[#8996A6] block text-[10px] uppercase font-semibold">Destination Target</span>
                  <span className="font-mono text-[#5B8DEF] font-bold text-sm block">
                    {activeIncident.destination_ip || activeIncident.dst_ip || (activeIncident.destination ? activeIncident.destination.split(':')[0] : 'Unknown')}
                    :
                    {activeIncident.destination_port !== undefined ? activeIncident.destination_port : (activeIncident.dport !== undefined ? activeIncident.dport : (activeIncident.destination && activeIncident.destination.includes(':') ? activeIncident.destination.split(':')[1] : '0'))}
                  </span>
                </div>
                <div>
                  <span className="text-[#8996A6] block text-[10px] uppercase font-semibold">Protocol / Service</span>
                  <span className="font-mono text-white font-bold text-sm block">
                    {activeIncident.protocol} ({activeIncident.service || (activeIncident.features && activeIncident.features['service']) || 'other'})
                  </span>
                </div>
                <div>
                  <span className="text-[#8996A6] block text-[10px] uppercase font-semibold">Threat Score / Severity</span>
                  <span className={`font-mono font-bold text-sm block ${activeIncident.threat_score > 60 ? 'text-[#EF6262]' : 'text-[#35C98A]'}`}>
                    {activeIncident.threat_score}/100 ({activeIncident.severity})
                  </span>
                </div>
              </div>

              {/* COMPROMISE ASSESSMENT (CRITICAL REQUIREMENT #18 & #8) */}
              <div className="p-4 rounded-xl bg-[#121A24] border border-[#25313E] space-y-2">
                <span className="text-xs font-bold text-[#F2B84B] uppercase tracking-wider block">
                  🛡️ Compromise Assessment & Attribution Boundary
                </span>
                <div className="text-xs text-[#E8EDF3] leading-relaxed space-y-1.5">
                  <p>
                    <strong>Assessment:</strong> Network threat detected. Host <code className="text-[#EF6262]">{activeIncident.source_ip || activeIncident.src_ip || (activeIncident.source ? activeIncident.source.split(':')[0] : 'Unknown')}</code> is a <strong>potentially affected host</strong> exhibiting anomalous connection behavior.
                  </p>
                  <p className="text-[#F2B84B] bg-[#080C12] p-2.5 rounded-lg border border-[#25313E]">
                    ⚠️ <strong>Compromise NOT confirmed:</strong> Network traffic alone cannot prove host compromise. Network observations demonstrate suspicious transport patterns but do not confirm adversary execution on the machine.
                  </p>
                  <p className="text-[#8996A6] text-[11px] pt-1">
                    <strong>Recommended Next Steps:</strong> Endpoint/EDR investigation on host {activeIncident.source_ip || activeIncident.src_ip || (activeIncident.source ? activeIncident.source.split(':')[0] : 'the affected host')}, user authentication log audit, running process inspection, memory dump analysis, and DNS proxy logs.
                  </p>
                </div>
              </div>

              {/* WHAT ENGINE 5 OBSERVED */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-[#E8EDF3] uppercase tracking-wider block">
                  📊 What Engine 5 Observed
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
                  {Object.entries(activeIncident.features || {}).slice(0, 9).map(([key, val]) => (
                    <div key={key} className="p-2 rounded bg-[#080C12] border border-[#25313E]">
                      <span className="text-[#64748B] block text-[10px] truncate">{key}</span>
                      <span className="text-white font-bold">{String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* WHY IT WAS FLAGGED (GINI / SHAP) */}
              {((activeIncident.verdict?.top_contributing_features && activeIncident.verdict.top_contributing_features.length > 0) || (activeIncident.top_factors && activeIncident.top_factors.length > 0)) && (
                <div className="space-y-2">
                  <span className="text-xs font-bold text-[#E8EDF3] uppercase tracking-wider block">
                    💡 Why It Was Flagged (Random Forest Gini Feature Contributions)
                  </span>
                  <div className="space-y-1.5">
                    {(activeIncident.verdict?.top_contributing_features || activeIncident.top_factors || []).map((feat, idx) => (
                      <div key={idx} className="p-2 rounded bg-[#080C12] border border-[#25313E] flex items-center justify-between text-xs">
                        <span className="text-[#E8EDF3] font-mono">{feat.feature} = {String(feat.observed_value)}</span>
                        <span className="text-[#93C5FD] font-mono font-bold">{(feat.importance * 100).toFixed(1)}% contribution</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* NETWORK EVIDENCE */}
              <div className="p-3 bg-[#080C12] rounded-lg border border-[#25313E] font-mono text-[11px] text-[#8996A6]">
                <span className="text-[#5B8DEF] font-bold block mb-1">Raw Dissection Summary:</span>
                <div>{activeIncident.summary || `${activeIncident.protocol} flow between ${activeIncident.source_ip || activeIncident.src_ip || 'Source'} and ${activeIncident.destination_ip || activeIncident.dst_ip || 'Destination'}`}</div>
                <div className="text-[10px] text-[#64748B] mt-1">
                  Packets in Flow: {activeIncident.packet_count || activeIncident.packets || 1} | TCP Flag: {activeIncident.flag || (activeIncident.features && activeIncident.features['flag']) || 'SF'} | Duration: {activeIncident.duration_sec !== undefined ? activeIncident.duration_sec : (activeIncident.features?.duration || 0)}s
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[#25313E] bg-[#121A24] flex justify-end">
              <button
                onClick={() => setActiveIncident(null)}
                className="px-4 py-2 rounded-lg bg-[#1F2937] hover:bg-[#2A374A] text-white text-xs font-semibold transition-colors"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
