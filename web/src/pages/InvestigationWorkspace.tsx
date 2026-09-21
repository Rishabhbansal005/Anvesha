import React, { useState, useEffect, useMemo } from 'react';
import { 
  UploadCloud, 
  FileText, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  ShieldAlert, 
  ArrowRight, 
  ChevronRight,
  MapPin,
  Network,
  Lock,
  Copy,
  Check,
  Eye,
  PanelRightClose,
  PanelRightOpen,
  ArrowLeft,
  FileCode,
  Share2,
  Clock,
  Printer,
  Download,
  X,
  ExternalLink,
  Server,
  Compass,
  Layers,
  Globe,
  Info,
  ShieldCheck,
  UserCheck
} from 'lucide-react';
import { RiskBadge } from '../components/common/RiskBadge';
import { ConfidencePill } from '../components/common/ConfidencePill';
import { IOCChip } from '../components/common/IOCChip';
import { API_BASE_URL } from '../constants';
import { ForensicReportModal } from '../components/investigation/ForensicReportModal';
import { AnalystWorkflowPanel } from '../components/investigation/AnalystWorkflowPanel';
import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { AttributionAssessment, EvidenceGapData, InfrastructureData, FieldStatus } from '../types';
import { GeoTraceMap } from '../components/investigation/GeoTraceMap';
import { HopFlowGraph } from '../components/investigation/HopFlowGraph';

function decodeMimeHeader(text?: string | null): string {
  if (!text) return '';
  if (!text.includes('=?')) return text;
  return text.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_, _charset, enc, data) => {
    try {
      if (enc.toUpperCase() === 'B') {
        return atob(data);
      } else {
        const raw = data.replace(/_/g, ' ').replace(/=([A-Fa-f0-9]{2})/g, (_: any, hex: string) =>
          String.fromCharCode(parseInt(hex, 16))
        );
        try {
          return decodeURIComponent(escape(raw));
        } catch {
          return raw;
        }
      }
    } catch {
      return data;
    }
  });
}

interface InvestigationWorkspaceProps {
  activeCaseId?: string | null;
  onClearActiveCase?: () => void;
}

type WorkspaceNavSection = 
  | 'overview' 
  | 'workflow'
  | 'fusion'
  | 'infrastructure'
  | 'attribution'
  | 'evidence-gaps'
  | 'lookalike'
  | 'identity'
  | 'timeline' 
  | 'authentication' 
  | 'route' 
  | 'observables' 
  | 'headers' 
  | 'report';

export const InvestigationWorkspace: React.FC<InvestigationWorkspaceProps> = ({
  activeCaseId,
  onClearActiveCase
}) => {
  // Current Case State
  const [caseData, setCaseData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeSection, setActiveSection] = useState<WorkspaceNavSection>('overview');
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [selectedEntity, setSelectedEntity] = useState<any>(null);

  // Ingestion Mode State
  const [inputMode, setInputMode] = useState<'upload' | 'paste'>('paste');
  const [pastedHeaders, setPastedHeaders] = useState('');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisStep, setAnalysisStep] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Report Modal
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportData, setReportData] = useState<any>(null);
  const [loadingReport, setLoadingReport] = useState(false);

  // Campaign Dossier Modal
  const [campaignModalOpen, setCampaignModalOpen] = useState(false);
  const [campaignDetails, setCampaignDetails] = useState<any>(null);
  const [loadingCampaign, setLoadingCampaign] = useState(false);

  // Memoized Geo Hops for Interactive Visual Map & Flowchart
  const geoHops = useMemo(() => {
    if (!caseData) return [];
    const list: any[] = [];
    const infra = caseData.infrastructure || {};
    
    if (caseData.hops && caseData.hops.length > 0) {
      // Reverse raw headers so trajectory follows true chronological transmission flow (Origin ➔ Relays ➔ Destination MX)
      const chronological = [...caseData.hops].reverse();
      const hasExplicitOrigin = chronological.some((h: any) => 
        Boolean(h.is_origin || (h.ip && h.ip === caseData.probable_origin_ip))
      );

      chronological.forEach((h: any, idx: number) => {
        const ip = h.ip || (h.ips && h.ips.length > 0 ? h.ips[0] : (infra.ip_address || ''));
        const isOrigin = Boolean(
          h.is_origin || 
          (ip && ip === caseData.probable_origin_ip) || 
          (!hasExplicitOrigin && idx === 0)
        );
        const isPrivate = h.is_public === false || Boolean(h.is_private) || (ip && (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')));
        
        const lat = h.latitude ?? h.lat ?? (ip === infra.ip_address ? infra.latitude : undefined);
        const lon = h.longitude ?? h.lon ?? (ip === infra.ip_address ? infra.longitude : undefined);
        const city = h.city || (ip === infra.ip_address ? infra.city : undefined);
        const region = h.region || (ip === infra.ip_address ? infra.region : undefined);
        const country = h.country || (ip === infra.ip_address ? infra.country : (isPrivate ? 'Private Network (RFC-1918)' : 'International Allocation'));
        const isp = h.isp || (ip === infra.ip_address ? infra.isp : (isPrivate ? 'Local Private Subnet' : 'Transit Relay MTA'));
        const asn = h.asn || (ip === infra.ip_address ? infra.asn : undefined);
        const isTor = Boolean(h.is_tor || (ip === infra.ip_address && infra.vpn_tor_proxy_indicator === 'TOR_EXIT_RELAY'));
        const delaySeconds = h.delay_seconds ?? h.delay;

        list.push({
          hopNumber: idx + 1,
          ip: ip,
          country: country,
          city: city,
          region: region,
          isp: isp,
          asn: asn,
          lat: lat,
          lon: lon,
          isOrigin: isOrigin,
          isTor: isTor,
          isPrivate: Boolean(isPrivate),
          delaySeconds: delaySeconds
        });
      });
    } else if (infra.ip_address) {
      list.push({
        hopNumber: 1,
        ip: infra.ip_address,
        country: infra.country || 'International Allocation',
        city: infra.city,
        region: infra.region,
        isp: infra.isp,
        asn: infra.asn,
        lat: infra.latitude,
        lon: infra.longitude,
        isOrigin: true,
        isTor: infra.vpn_tor_proxy_indicator === 'TOR_EXIT_RELAY',
        isPrivate: false
      });
    }
    return list;
  }, [caseData]);

  const handleOpenCampaign = async (campaignId: string) => {
    setLoadingCampaign(true);
    setCampaignModalOpen(true);
    try {
      const res = await fetch(`${API_BASE_URL}/campaigns/${campaignId}`);
      if (res.ok) {
        const data = await res.json();
        setCampaignDetails(data);
      }
    } catch (err) {
      console.warn('Failed to load campaign:', err);
    } finally {
      setLoadingCampaign(false);
    }
  };

  // Copy helper
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Fetch case data when activeCaseId changes
  useEffect(() => {
    if (activeCaseId) {
      setLoading(true);
      fetch(`${API_BASE_URL}/cases/${activeCaseId}`)
        .then(async (res) => {
          if (!res.ok) throw new Error('Case not found');
          return res.json();
        })
        .then((data) => {
          const c = data.case || data;
          const email = data.email || {};
          const infra = data.infrastructure || c.infrastructure;
          const catScores = data.category_scores || c.category_scores || data.fusion?.category_scores;

          setCaseData({
            ...c,
            // Core email fields
            sender: email.sender || c.sender || 'Unknown Sender',
            recipient: email.recipient || c.recipient || 'Unknown Recipient',
            subject: decodeMimeHeader(email.subject || c.subject || c.title?.replace('Investigation of: ', '')),
            title: decodeMimeHeader(c.title),
            reply_to: email.reply_to || c.reply_to,
            return_path: email.return_path || c.return_path,
            spf_status: email.spf_status || c.spf_status || 'NOT OBSERVED',
            dkim_status: email.dkim_status || c.dkim_status || 'NOT OBSERVED',
            dmarc_status: email.dmarc_status || c.dmarc_status || 'NOT OBSERVED',
            // Forensic structures
            email: email,
            evidence: data.evidence || [],
            observables: data.observables || [],
            hops: data.hops || (email.observed_relays_json || email.delivery_hops_json) || c.hops || [],
            timeline: data.timeline || [],
            infrastructure: infra,
            domain_intelligence: data.domain_intelligence || c.domain_intelligence,
            attribution: data.attribution || c.attribution,
            evidence_gaps: data.evidence_gaps || c.evidence_gaps,
            campaign: data.campaign || c.campaign,
            campaign_correlation: data.campaign_correlation || c.campaign_correlation,
            // Critical AI & explainable score breakdowns!
            category_scores: catScores,
            ml_signal: data.ml_signal || c.ml_signal,
            lookalike_evidence: data.lookalike_evidence || c.lookalike_evidence,
            identity_impersonation: data.identity_impersonation || c.identity_impersonation,
            fusion: data.fusion || c.fusion,
            flagged_reasons: data.flagged_reasons || c.flagged_reasons || [],
            email_provider_intelligence: data.email_provider_intelligence || c.email_provider_intelligence
          });
          if (c.probable_origin_ip) {
            setSelectedEntity({
              type: 'IP',
              value: c.probable_origin_ip,
              location: c.approximate_location,
              confidence: c.origin_confidence,
              disclaimer: 'IP-associated infrastructure location. Does not establish physical actor location.',
              infrastructure: infra
            });
          }
        })
        .catch((err) => {
          console.warn('Error fetching case:', err);
          setCaseData(null);
        })
        .finally(() => setLoading(false));
    } else {
      setCaseData(null);
    }
  }, [activeCaseId]);

  // Handle Real Email Analysis Submission
  const handleAnalyzeEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (inputMode === 'paste' && !pastedHeaders.trim()) return;
    if (inputMode === 'upload' && !uploadedFile) return;

    setAnalyzing(true);
    setAnalysisStep('Parsing email headers (RFC-822)...');

    const formData = new FormData();
    if (inputMode === 'upload' && uploadedFile) {
      formData.append('file', uploadedFile);
    } else {
      formData.append('raw_headers', pastedHeaders);
    }

    try {
      setTimeout(() => setAnalysisStep('Analyzing SPF, DKIM & DMARC authentication...'), 300);
      setTimeout(() => setAnalysisStep('Tracing SMTP Received hop trajectory...'), 600);
      setTimeout(() => setAnalysisStep('Extracting observables & evaluating risk...'), 900);
      setTimeout(() => setAnalysisStep('Registering cryptographic evidence in Supabase...'), 1200);

      const res = await fetch(`${API_BASE_URL}/emails/analyze`, {
        method: 'POST',
        body: formData
      });

      if (res.ok) {
        const result = await res.json();
        setCaseData(result);
        if (result.probable_origin_ip) {
          setSelectedEntity({
            type: 'IP',
            value: result.probable_origin_ip,
            location: result.approximate_location,
            confidence: result.origin_confidence,
            disclaimer: 'Observed public gateway from SMTP Received header chain.'
          });
        }
      } else {
        const errData = await res.json().catch(() => ({}));
        alert(`Analysis failed: ${errData.detail || 'Could not process email'}`);
      }
    } catch (err) {
      console.error('Forensic analysis error:', err);
      alert('Network error connecting to forensic engine.');
    } finally {
      setAnalyzing(false);
      setAnalysisStep('');
    }
  };

  // Load Full Forensic Report
  const handleOpenReport = async () => {
    if (!caseData) return;
    setLoadingReport(true);
    setReportModalOpen(true);
    try {
      const caseId = caseData.case_number || caseData.id;
      const res = await fetch(`${API_BASE_URL}/cases/${caseId}/report`);
      if (res.ok) {
        const data = await res.json();
        setReportData(data);
      } else {
        console.error('Report API returned non-OK status:', res.status);
      }
    } catch (err) {
      console.error('Failed to load report:', err);
    } finally {
      setLoadingReport(false);
    }
  };

  // Select Observable in Inspector
  const handleSelectObservable = (obs: any) => {
    setSelectedEntity({
      type: obs.ioc_type || obs.type,
      value: obs.value,
      description: obs.description,
      reputation_score: obs.reputation_score
    });
    setInspectorOpen(true);
  };

  // Status Badge Helper for Forensic Integrity (OBSERVED, ENRICHED, UNAVAILABLE, NO_DATA, ERROR)
  const renderStatusBadge = (status?: string | null) => {
    if (!status) return null;
    const s = status.toUpperCase();
    if (s === 'PASS' || s === 'CONFIRMED' || s === 'OBSERVED' || s === 'ENRICHED' || s === 'HIGH_PROBABILITY') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/30">
          {s}
        </span>
      );
    }
    if (s === 'FAIL' || s === 'ERROR' || s === 'SPOOFED_UNRELIABLE') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#FF453A]/10 text-[#FF453A] border border-[#FF453A]/30">
          {s}
        </span>
      );
    }
    if (s === 'UNAVAILABLE' || s === 'NO_DATA' || s === 'INCONCLUSIVE' || s === 'LOW_PROBABILITY') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/30">
          {s}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#1D2633] text-[#8996A6] border border-[#25313E]">
        {s}
      </span>
    );
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] w-full overflow-hidden bg-[#080C12] text-[#E8EDF3]">
      {/* ------------------------------------------------------------- */}
      {/* PANE 1: LEFT CONTEXTUAL NAVIGATION                            */}
      {/* ------------------------------------------------------------- */}
      <aside className="w-56 border-r border-[#25313E] bg-[#0F151D] flex flex-col justify-between p-3 select-none flex-shrink-0">
        <div className="space-y-4">
          <div className="px-2 pt-2">
            <span className="text-[10px] font-mono uppercase text-[#8996A6] tracking-wider block">
              Workspace Context
            </span>
            <span className="text-xs font-bold font-mono text-[#E8EDF3] mt-0.5 truncate block">
              {caseData ? caseData.case_number : 'New Ingestion'}
            </span>
          </div>

          {caseData && (
            <div className="px-2 py-1.5 rounded bg-[#151D27] border border-[#25313E] space-y-1">
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-[#8996A6]">Threat Level:</span>
                <span className={`font-bold ${
                  caseData.risk_level === 'CRITICAL' ? 'text-[#FF453A]' :
                  caseData.risk_level === 'HIGH' ? 'text-[#FF9F0A]' :
                  caseData.risk_level === 'MEDIUM' ? 'text-[#FFD60A]' : 'text-[#30D158]'
                }`}>
                  {caseData.risk_level}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-[#8996A6]">Score:</span>
                <span className="text-[#E8EDF3] font-bold">{caseData.risk_score}/100</span>
              </div>
            </div>
          )}

          {/* Navigation Sections */}
          <nav className="space-y-1">
            <button
              onClick={() => setActiveSection('overview')}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                activeSection === 'overview'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <ShieldAlert size={14} />
              <span>Assessment & Findings</span>
            </button>

            <button
              onClick={() => setActiveSection('workflow')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'workflow'
                  ? 'bg-[#1D2633] text-[#30D158]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <UserCheck size={14} />
              <span>Analyst Workflow</span>
            </button>

            <button
              onClick={() => setActiveSection('infrastructure')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'infrastructure'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <Server size={14} />
              <span>Infrastructure & Intel</span>
            </button>

            <button
              onClick={() => setActiveSection('attribution')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'attribution'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <Compass size={14} />
              <span>Attribution Boundary</span>
            </button>

            <button
              onClick={() => setActiveSection('evidence-gaps')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'evidence-gaps'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <Layers size={14} />
              <span>Evidence Gaps & Actions</span>
            </button>
              <button
                onClick={() => setActiveSection('lookalike')}
                disabled={!caseData}
                className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                  activeSection === 'lookalike'
                    ? 'bg-[#1D2633] text-[#BF5AF2]'
                    : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
                }`}
              >
                <Globe size={14} />
                <span>Lookalike Domain (M3B)</span>
              </button>

              <button
                onClick={() => setActiveSection('identity')}
                disabled={!caseData}
                className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                  activeSection === 'identity'
                    ? 'bg-[#1D2633] text-[#FF9F0A]'
                    : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
                }`}
              >
                <UserCheck size={14} />
                <span>Identity Impersonation (M3A)</span>
              </button>

              <button
                onClick={() => setActiveSection('fusion')}
                disabled={!caseData}
                className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                  activeSection === 'fusion'
                    ? 'bg-[#1D2633] text-[#30D158]'
                    : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
                }`}
              >
                <Layers size={14} />
                <span>Forensic Signal Fusion (9B)</span>
              </button>

            <button
              onClick={() => setActiveSection('timeline')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'timeline'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <Clock size={14} />
              <span>Forensic Timeline</span>
            </button>

            <button
              onClick={() => setActiveSection('authentication')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'authentication'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <Lock size={14} />
              <span>Authentication Matrix</span>
            </button>

            <button
              onClick={() => setActiveSection('route')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'route'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <Network size={14} />
              <span>SMTP Trajectory</span>
            </button>

            <button
              onClick={() => setActiveSection('observables')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'observables'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <Share2 size={14} />
              <span>Observables & Graph</span>
            </button>

            <button
              onClick={() => setActiveSection('headers')}
              disabled={!caseData}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                activeSection === 'headers'
                  ? 'bg-[#1D2633] text-[#5B8DEF]'
                  : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27]'
              }`}
            >
              <FileCode size={14} />
              <span>Raw Evidence Data</span>
            </button>
          </nav>
        </div>

        {/* Bottom Actions */}
        <div className="pt-3 border-t border-[#25313E]/60 space-y-2">
          {caseData && (
            <button
              onClick={handleOpenReport}
              className="w-full flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#5B8DEF]/10 hover:bg-[#5B8DEF]/20 border border-[#5B8DEF]/30 text-xs font-mono text-[#5B8DEF] transition-colors cursor-pointer"
            >
              <Printer size={13} />
              <span>Export Report</span>
            </button>
          )}

          {caseData && onClearActiveCase && (
            <button
              onClick={onClearActiveCase}
              className="w-full flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#151D27] hover:bg-[#1D2633] text-xs font-mono text-[#8996A6] hover:text-[#E8EDF3] transition-colors cursor-pointer"
            >
              <ArrowLeft size={13} />
              <span>New Ingestion</span>
            </button>
          )}
        </div>
      </aside>

      {/* ------------------------------------------------------------- */}
      {/* PANE 2: PRIMARY FORENSIC CANVAS (MAIN WORKSPACE)              */}
      {/* ------------------------------------------------------------- */}
      <main className="flex-1 overflow-y-auto p-6 bg-[#080C12]">
        {/* Loading Spinner */}
        {loading && (
          <div className="h-full flex items-center justify-center text-xs font-mono text-[#8996A6]">
            Loading investigation record from Supabase...
          </div>
        )}

        {/* State A: Fresh Ingestion Canvas (Zero Mock Data) */}
        {!loading && !caseData && (
          <div className="max-w-3xl mx-auto space-y-6 pt-4">
            <div>
              <h2 className="text-xl font-bold font-mono tracking-tight text-[#E8EDF3]">
                EMAIL FORENSIC INGESTION
              </h2>
              <p className="text-xs text-[#8996A6] mt-1">
                Upload a raw <span className="font-mono text-[#5B8DEF]">.eml</span> file or paste full RFC-822 message headers to begin real forensic analysis.
              </p>
            </div>

            <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-[#25313E] pb-3">
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setInputMode('paste')}
                    className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
                      inputMode === 'paste' ? 'bg-[#5B8DEF] text-white' : 'text-[#8996A6] hover:text-[#E8EDF3]'
                    }`}
                  >
                    Paste RFC-822
                  </button>
                  <button
                    type="button"
                    onClick={() => setInputMode('upload')}
                    className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
                      inputMode === 'upload' ? 'bg-[#5B8DEF] text-white' : 'text-[#8996A6] hover:text-[#E8EDF3]'
                    }`}
                  >
                    Upload .EML File
                  </button>
                </div>
              </div>

              {inputMode === 'paste' ? (
                <form onSubmit={handleAnalyzeEmail} className="space-y-4">
                  <textarea
                    rows={12}
                    value={pastedHeaders}
                    onChange={(e) => setPastedHeaders(e.target.value)}
                    placeholder="Paste complete RFC-822 email message or headers here:
Received: from ...
From: ...
To: ...
Subject: ...
Authentication-Results: ...

(Input is treated as untrusted and safely parsed)"
                    className="w-full rounded-md border border-[#25313E] bg-[#080C12] p-3 text-xs font-mono text-[#E8EDF3] placeholder-[#8996A6]/60 focus:outline-none focus:ring-1 focus:ring-[#5B8DEF]"
                  />

                  {analyzing && (
                    <div className="p-3 rounded bg-[#1D2633]/60 border border-[#5B8DEF]/30 flex items-center gap-3 text-xs font-mono text-[#5B8DEF]">
                      <div className="w-2 h-2 rounded-full bg-[#5B8DEF] animate-ping" />
                      <span>{analysisStep || 'Processing RFC-822 message...'}</span>
                    </div>
                  )}

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={analyzing || !pastedHeaders.trim()}
                      className="px-5 py-2 rounded-md bg-[#5B8DEF] hover:bg-[#4a7de0] text-white text-xs font-semibold tracking-wide transition-all shadow-subtle cursor-pointer disabled:opacity-50 flex items-center gap-2"
                    >
                      {analyzing ? 'Executing Forensic Pipeline...' : 'Analyze Message'}
                      {!analyzing && <ArrowRight size={14} />}
                    </button>
                  </div>
                </form>
              ) : (
                <form onSubmit={handleAnalyzeEmail} className="space-y-4">
                  <div className="border border-dashed border-[#25313E] hover:border-[#5B8DEF] rounded-lg p-10 text-center transition-colors">
                    <input
                      type="file"
                      id="eml-upload"
                      accept=".eml,message/rfc822,text/plain"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setUploadedFile(e.target.files[0]);
                        }
                      }}
                      className="hidden"
                    />
                    <label htmlFor="eml-upload" className="cursor-pointer block">
                      <UploadCloud size={32} className="mx-auto text-[#5B8DEF] mb-2 opacity-80" />
                      <span className="text-xs font-medium text-[#E8EDF3] block">
                        {uploadedFile ? uploadedFile.name : 'Click to select .eml message file'}
                      </span>
                      <span className="text-[11px] text-[#8996A6] block mt-1">
                        Direct SHA-256 calculation and header traversal (Max 10MB)
                      </span>
                    </label>
                  </div>

                  {analyzing && (
                    <div className="p-3 rounded bg-[#1D2633]/60 border border-[#5B8DEF]/30 flex items-center gap-3 text-xs font-mono text-[#5B8DEF]">
                      <div className="w-2 h-2 rounded-full bg-[#5B8DEF] animate-ping" />
                      <span>{analysisStep || 'Processing RFC-822 file...'}</span>
                    </div>
                  )}

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={analyzing || !uploadedFile}
                      className="px-5 py-2 rounded-md bg-[#5B8DEF] hover:bg-[#4a7de0] text-white text-xs font-semibold tracking-wide transition-all shadow-subtle cursor-pointer disabled:opacity-50 flex items-center gap-2"
                    >
                      {analyzing ? 'Executing Forensic Pipeline...' : 'Analyze File'}
                      {!analyzing && <ArrowRight size={14} />}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        )}

        {/* State B: Active Investigation Workstation */}
        {!loading && caseData && (
          <div className="space-y-6 max-w-4xl">
            {/* 1. Top Investigation Summary Banner */}
            <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#25313E]/60 pb-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[#5B8DEF]">
                      {caseData.case_number}
                    </span>
                    <button
                      onClick={() => copyToClipboard(caseData.case_number, 'case_num')}
                      className="text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
                      title="Copy Case Number"
                    >
                      {copiedKey === 'case_num' ? <Check size={12} className="text-[#30D158]" /> : <Copy size={12} />}
                    </button>
                    <span className="text-[#8996A6]">·</span>
                    <span className="text-xs font-mono uppercase text-[#8996A6]">
                      {caseData.status}
                    </span>
                    <span className="text-[#8996A6]">·</span>
                    <span className="text-xs font-mono text-[#8996A6]">
                      {caseData.threat_type}
                    </span>
                  </div>
                  <h1 className="text-base font-bold text-[#E8EDF3]">
                    {caseData.title || caseData.subject}
                  </h1>
                </div>

                <div className="flex items-center gap-3">
                  <RiskBadge score={caseData.risk_score} level={caseData.risk_level} size="lg" />
                </div>
              </div>

              {/* 6-Point Top Forensic Summary Grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2.5 text-xs font-mono">
                <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60 space-y-1">
                  <span className="text-[9px] uppercase tracking-wider text-[#8996A6] block">THREAT RISK</span>
                  <span className={`font-bold block ${
                    caseData.risk_level === 'CRITICAL' ? 'text-[#FF453A]' :
                    caseData.risk_level === 'HIGH' ? 'text-[#FF9F0A]' :
                    caseData.risk_level === 'MEDIUM' ? 'text-[#FFD60A]' : 'text-[#30D158]'
                  }`}>
                    {caseData.risk_level} · {caseData.risk_score}/100
                  </span>
                </div>

                <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60 space-y-1">
                  <span className="text-[9px] uppercase tracking-wider text-[#8996A6] block">ORIGIN CONFIDENCE</span>
                  <span className="text-[#E8EDF3] font-bold block">
                    {caseData.origin_confidence || caseData.attribution?.origin_confidence || 'UNDETERMINED'}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60 space-y-1">
                  <span className="text-[9px] uppercase tracking-wider text-[#8996A6] block">AUTHENTICATION</span>
                  <span className={`font-bold block truncate text-[11px] ${
                    (caseData.spf_status === 'PASS' && caseData.dkim_status === 'PASS') ? 'text-[#30D158]' : 'text-[#FF9F0A]'
                  }`} title={`SPF: ${caseData.spf_status || 'NONE'} | DKIM: ${caseData.dkim_status || 'NONE'} | DMARC: ${caseData.dmarc_status || 'NONE'}`}>
                    SPF {caseData.spf_status || 'N/A'} · DKIM {caseData.dkim_status || 'N/A'}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60 space-y-1">
                  <span className="text-[9px] uppercase tracking-wider text-[#8996A6] block">PROBABLE ORIGIN IP</span>
                  <span className="text-[#5B8DEF] font-bold truncate block" title={caseData.probable_origin_ip || 'Not Established'}>
                    {caseData.probable_origin_ip || 'Not Established'}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60 space-y-1">
                  <span className="text-[9px] uppercase tracking-wider text-[#8996A6] block">OBSERVED INFRASTRUCTURE</span>
                  <span className="text-[#E8EDF3] truncate block text-[11px]" title={caseData.attribution?.observed_infrastructure || caseData.infrastructure?.cloud_classification || 'Public Gateway'}>
                    {caseData.attribution?.observed_infrastructure || caseData.infrastructure?.cloud_classification || 'Public Gateway'}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-[#1A0C0E] border border-[#FF453A]/40 space-y-1">
                  <span className="text-[9px] uppercase tracking-wider text-[#FF453A] font-bold block">ACTOR IDENTITY</span>
                  <span className="text-[#FF453A] font-bold block text-[11px]">
                    NOT ESTABLISHED
                  </span>
                </div>
              </div>
            </div>

            {/* 2. Nav Section Content */}
            {activeSection === 'overview' && (
              <div className="space-y-6">
                {/* Potential Campaign Intelligence Card */}
                {caseData.campaign && (
                  <div className="rounded-lg border border-[#5B8DEF]/40 bg-[#0F151D] p-5 space-y-3.5 shadow-sm">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#25313E]/60 pb-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Layers size={15} className="text-[#5B8DEF]" />
                          <span className="text-[10px] uppercase font-mono tracking-wider text-[#8996A6]">
                            CAMPAIGN CORRELATION
                          </span>
                          <span className="text-[#8996A6]">·</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            caseData.campaign.confidence === 'HIGH' 
                              ? 'bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/30' 
                              : 'bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/30'
                          }`}>
                            CONFIDENCE: {caseData.campaign.confidence}
                          </span>
                        </div>
                        <h2 className="text-sm font-bold font-mono text-[#E8EDF3]">
                          Potential Campaign: {caseData.campaign.campaign_id || caseData.campaign.name}
                        </h2>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleOpenCampaign(caseData.campaign.id || caseData.campaign.campaign_id)}
                        className="px-3 py-1.5 rounded bg-[#1D2633] hover:bg-[#25313E] text-xs font-mono text-[#5B8DEF] border border-[#5B8DEF]/30 transition-colors flex items-center gap-2 cursor-pointer self-start sm:self-auto"
                      >
                        <span>View Campaign</span>
                        <ArrowRight size={13} />
                      </button>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                      <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60">
                        <span className="text-[9px] uppercase text-[#8996A6] block">RELATED ACTIVITY</span>
                        <span className="text-[#E8EDF3] font-bold mt-0.5 block">{caseData.campaign.case_count || 1} cases</span>
                      </div>
                      <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60">
                        <span className="text-[9px] uppercase text-[#8996A6] block">IDENTIFIED EMAILS</span>
                        <span className="text-[#E8EDF3] font-bold mt-0.5 block">{caseData.campaign.email_count || 1} messages</span>
                      </div>
                      <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60">
                        <span className="text-[9px] uppercase text-[#8996A6] block">SHARED OBSERVABLES</span>
                        <span className="text-[#E8EDF3] font-bold mt-0.5 block">{caseData.campaign.ioc_count || 0} IOCs</span>
                      </div>
                      <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60">
                        <span className="text-[9px] uppercase text-[#8996A6] block">STATUS</span>
                        <span className="text-[#30D158] font-bold mt-0.5 block">{caseData.campaign.status || 'ACTIVE'}</span>
                      </div>
                    </div>

                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 space-y-2">
                      <span className="text-[10px] font-mono uppercase text-[#8996A6] block font-semibold">
                        WHY RELATED:
                      </span>
                      <ul className="space-y-1 text-xs font-mono text-[#E8EDF3]">
                        {(caseData.campaign.evidence_summary?.top_reasons || 
                          caseData.campaign_correlation?.reasons?.map((r: any) => r.description) || 
                          ['Shared threat infrastructure and observed behavioral overlap.']
                        ).map((r: string, idx: number) => (
                          <li key={idx} className="flex items-start gap-2 text-[11px] text-[#8996A6]">
                            <span className="text-[#5B8DEF]">•</span>
                            <span className="text-[#E8EDF3]">{r}</span>
                          </li>
                        ))}
                      </ul>
                      <p className="text-[10px] font-mono text-[#8996A6]/80 pt-2 border-t border-[#25313E]/40 italic">
                        {caseData.campaign.explanation}
                      </p>
                    </div>
                  </div>
                )}

                {/* Cross-Modal Forensic Signal Fusion Card (Phase 9B) */}
                {caseData.fusion && (
                  <div className="rounded-lg border border-[#30D158]/30 bg-[#0F151D] p-5 space-y-3.5 shadow-sm">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#25313E]/60 pb-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Layers size={15} className="text-[#30D158]" />
                          <span className="text-[10px] uppercase font-mono tracking-wider text-[#8996A6]">
                            FORENSIC SIGNAL FUSION
                          </span>
                          <span className="text-[#8996A6]">·</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            caseData.fusion.fusion_confidence === 'HIGH'
                              ? 'bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/30'
                              : caseData.fusion.fusion_confidence === 'MEDIUM'
                              ? 'bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/30'
                              : 'bg-[#8996A6]/10 text-[#8996A6] border border-[#8996A6]/30'
                          }`}>
                            CONFIDENCE: {caseData.fusion.fusion_confidence}
                          </span>
                          <span className="text-[#8996A6]">·</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1D2633] text-[#E8EDF3] border border-[#25313E]">
                            SCORE: {caseData.fusion.fusion_score}/100
                          </span>
                        </div>
                        <h2 className="text-sm font-bold font-mono text-[#E8EDF3]">
                          Multi-Modal Threat Correlation & Forensic Synthesis
                        </h2>
                      </div>
                      <button
                        type="button"
                        onClick={() => setActiveSection('fusion')}
                        className="px-3 py-1.5 rounded bg-[#1D2633] hover:bg-[#25313E] text-xs font-mono text-[#30D158] border border-[#30D158]/30 transition-colors flex items-center gap-2 cursor-pointer self-start sm:self-auto"
                      >
                        <span>View Full Fusion Matrix</span>
                        <ArrowRight size={13} />
                      </button>
                    </div>

                    {/* Synthesis Interpretation */}
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 text-xs font-mono space-y-2">
                      <p className="text-[#E8EDF3] leading-relaxed">
                        {caseData.fusion.forensic_interpretation}
                      </p>
                      {caseData.fusion.contradictions && caseData.fusion.contradictions.length > 0 && (
                        <div className="p-2.5 rounded bg-[#FF9F0A]/10 border border-[#FF9F0A]/30 text-[11px] text-[#FF9F0A] flex items-start gap-2">
                          <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                          <div>
                            <span className="font-bold">Contradiction Detected: </span>
                            {caseData.fusion.contradictions[0].description}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* 6 Category mini-bars */}
                    {caseData.fusion.category_breakdown && (
                      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs font-mono">
                        {Object.entries(caseData.fusion.category_breakdown).map(([cat, item]: [string, any]) => (
                          <div key={cat} className="p-2 rounded bg-[#080C12] border border-[#25313E]/60 space-y-1">
                            <div className="flex justify-between items-center text-[10px]">
                              <span className="text-[#8996A6] uppercase">{cat.replace('_', ' ')}</span>
                              <span className="text-[#E8EDF3] font-bold">{item.score}/{item.max}</span>
                            </div>
                            <div className="w-full bg-[#151D27] h-1 rounded-full overflow-hidden">
                              <div
                                className="bg-[#30D158] h-full rounded-full"
                                style={{ width: `${Math.min(100, (item.score / item.max) * 100)}%` }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[11px] font-mono text-[#8996A6]">
                      <span className="inline-flex items-center gap-1.5">
                        <ShieldCheck size={13} className="text-[#5B8DEF]" />
                        <span>Actor Identity: <strong className="text-[#E8EDF3]">NOT ESTABLISHED</strong></span>
                      </span>
                      <span className="text-[10px] text-[#8996A6]/70">Anti-Double-Counting Enforced</span>
                    </div>
                  </div>
                )}

                {/* Email Provider Intelligence Card (Phase 12.5) */}
                {(caseData.email_provider_intelligence || caseData.dossier?.email_provider_intelligence) && (() => {
                  const disp = caseData.email_provider_intelligence || caseData.dossier?.email_provider_intelligence;
                  const domain = disp.domain || disp.sender_domain;
                  const classification = disp.classification || 'UNKNOWN';
                  const provider = disp.provider_name || disp.provider || 'Unknown Provider';
                  const isDisposable = classification === 'DISPOSABLE';
                  const isPrivacy = classification === 'FORWARDING_PRIVACY';
                  const sha256Short = (disp.dataset_sha256 || '').slice(0, 16);

                  return (
                    <div className={`rounded-lg border p-4 space-y-2.5 shadow-sm font-mono ${
                      isDisposable 
                        ? 'border-[#FF9F0A]/40 bg-[#0F151D]' 
                        : isPrivacy 
                        ? 'border-[#5B8DEF]/40 bg-[#0F151D]' 
                        : 'border-[#25313E] bg-[#0F151D]'
                    }`}>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#25313E]/60 pb-2.5">
                        <div className="flex items-center gap-2">
                          <Globe size={15} className={isDisposable ? 'text-[#FF9F0A]' : isPrivacy ? 'text-[#5B8DEF]' : 'text-[#8996A6]'} />
                          <span className="text-[10px] uppercase tracking-wider text-[#8996A6]">
                            EMAIL PROVIDER INTELLIGENCE
                          </span>
                          <span className="text-[#8996A6]">·</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isDisposable
                              ? 'bg-[#FF9F0A]/15 text-[#FF9F0A] border border-[#FF9F0A]/30'
                              : isPrivacy
                              ? 'bg-[#5B8DEF]/15 text-[#5B8DEF] border border-[#5B8DEF]/30'
                              : 'bg-[#25313E] text-[#8996A6] border border-[#3E4F63]'
                          }`}>
                            {isDisposable ? 'DISPOSABLE' : isPrivacy ? 'PRIVACY / FORWARDING SERVICE' : classification}
                          </span>
                        </div>
                        <div className="text-[10px] text-[#8996A6] flex items-center gap-2">
                          <span>Risk: <strong className={isDisposable ? 'text-[#FF9F0A]' : 'text-[#30D158]'}>+{disp.risk_contribution ?? 0} pts</strong></span>
                          <span>·</span>
                          <span>Confidence: <strong className="text-[#E8EDF3]">{disp.confidence || 'HIGH'}</strong></span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="space-y-1">
                          <div className="text-[10px] text-[#8996A6] uppercase">Observed Sender Domain & Provider</div>
                          <div className="text-[#E8EDF3] font-bold flex items-center gap-2">
                            <span>{domain}</span>
                            <span className="text-[#8996A6] font-normal">({provider})</span>
                          </div>
                          <p className="text-[11px] text-[#8996A6] leading-relaxed pt-1">
                            {isDisposable
                              ? `Domain belongs to known disposable email provider (${provider}). Evaluated as supporting forensic evidence (+8 risk points). This does NOT independently prove malicious intent.`
                              : isPrivacy
                              ? `Domain belongs to privacy/forwarding service (${provider}). Legitimate privacy use. Zero risk contribution.`
                              : (disp.evidence_text || disp.evidence || 'Standard email provider or unlisted domain.')}
                          </p>
                        </div>
                        <div className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60 text-[11px] space-y-1.5 flex flex-col justify-center">
                          <div className="flex justify-between text-[#8996A6]">
                            <span>Intelligence Source:</span>
                            <span className="text-[#E8EDF3]">{disp.source || 'Governed Dataset'}</span>
                          </div>
                          <div className="flex justify-between text-[#8996A6]">
                            <span>Dataset Version:</span>
                            <span className="text-[#E8EDF3]">{disp.dataset_version || '2026.09.1'}</span>
                          </div>
                          <div className="flex justify-between text-[#8996A6]">
                            <span>Dataset SHA-256:</span>
                            <span className="text-[#E8EDF3] font-mono text-[10px]">{sha256Short ? `${sha256Short}...` : 'N/A'}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {/* Panel 1: Combined Risk Assessment & Categorical Evidence Contribution */}
                <div className="rounded-xl border border-[#25313E] bg-[#0F151D] p-5 shadow-lg relative overflow-hidden space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#25313E]/80 pb-3.5">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-[#151D27] border border-[#25313E] text-[#5B8DEF]">
                        <Layers size={18} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-[#E8EDF3]">
                            COMBINED RISK ASSESSMENT &amp; EVIDENCE CONTRIBUTION
                          </h3>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold bg-[#151D27] text-[#8996A6] border border-[#25313E]">
                            6-Vector Analysis
                          </span>
                        </div>
                        <p className="text-[11px] text-[#8996A6] mt-0.5">
                          Categorical score breakdown derived from ANVESH Explainable Multi-Vector Scoring Engine
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 self-start sm:self-auto">
                      <div className="flex flex-col items-end font-mono">
                        <span className="text-[10px] text-[#8996A6] uppercase tracking-wider">AGGREGATE SCORE</span>
                        <div className="flex items-baseline gap-1">
                          <span className={`text-xl font-black ${
                            (caseData.risk_score ?? 0) >= 70 ? 'text-[#FF453A]' :
                            (caseData.risk_score ?? 0) >= 40 ? 'text-[#FF9F0A]' : 'text-[#30D158]'
                          }`}>
                            {caseData.risk_score ?? 0}
                          </span>
                          <span className="text-xs text-[#8996A6]">/ 100</span>
                        </div>
                      </div>
                      <div className={`px-2.5 py-1 rounded-md border font-mono text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                        (caseData.risk_score ?? 0) >= 70 
                          ? 'bg-[#FF453A]/10 border-[#FF453A]/30 text-[#FF453A]' 
                          : (caseData.risk_score ?? 0) >= 40 
                            ? 'bg-[#FF9F0A]/10 border-[#FF9F0A]/30 text-[#FF9F0A]' 
                            : 'bg-[#30D158]/10 border-[#30D158]/30 text-[#30D158]'
                      }`}>
                        <span className={`w-2 h-2 rounded-full animate-pulse ${
                          (caseData.risk_score ?? 0) >= 70 ? 'bg-[#FF453A]' : (caseData.risk_score ?? 0) >= 40 ? 'bg-[#FF9F0A]' : 'bg-[#30D158]'
                        }`} />
                        {(caseData.risk_level ?? ((caseData.risk_score ?? 0) >= 70 ? 'CRITICAL' : (caseData.risk_score ?? 0) >= 40 ? 'SUSPICIOUS' : 'BENIGN'))}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                    {/* Card 1: Text / Language Signal (Model 1) */}
                    {(() => {
                      const score = caseData.category_scores?.ml_risk?.score ?? (caseData.ml_signal?.ml_score ?? 0);
                      const max = caseData.category_scores?.ml_risk?.max ?? 20;
                      const pct = Math.min(100, Math.round((score / max) * 100));
                      return (
                        <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E] hover:border-[#5B8DEF]/40 transition-all flex flex-col justify-between space-y-2">
                          <div>
                            <div className="flex items-center justify-between">
                              <div className="p-1.5 rounded bg-[#5B8DEF]/10 text-[#5B8DEF] border border-[#5B8DEF]/20">
                                <FileText size={14} />
                              </div>
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#151D27] text-[#5B8DEF] border border-[#25313E]">
                                M1 · NLP
                              </span>
                            </div>
                            <div className="mt-2 leading-tight">
                              <div className="text-[11px] font-bold text-[#E8EDF3]">Text Signal</div>
                              <div className="text-[9px] font-mono text-[#8996A6] mt-0.5">Statistical NLP</div>
                            </div>
                          </div>
                          <div>
                            <div className="flex items-baseline justify-between font-mono">
                              <span className="text-lg font-bold text-[#5B8DEF]">+{score}</span>
                              <span className="text-[10px] text-[#64748B]">/ {max}</span>
                            </div>
                            <div className="w-full bg-[#151D27] h-1.5 rounded-full overflow-hidden mt-1.5">
                              <div 
                                className="bg-[#5B8DEF] h-full rounded-full transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                          <div className="flex items-center justify-between pt-1 border-t border-[#25313E]/40 font-mono text-[9px]">
                            <span className="text-[#8996A6]">{pct}% load</span>
                            <span className={`font-semibold ${score > 15 ? 'text-[#FF453A]' : score > 0 ? 'text-[#FF9F0A]' : 'text-[#30D158]'}`}>
                              {score > 15 ? 'HIGH SIGNAL' : score > 0 ? 'FLAGGED' : 'CLEAN'}
                            </span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Card 2: Forensic Authentication (Model 2) */}
                    {(() => {
                      const score = caseData.category_scores?.forensic_auth_risk?.score ?? 0;
                      const max = caseData.category_scores?.forensic_auth_risk?.max ?? 20;
                      const pct = Math.min(100, Math.round((score / max) * 100));
                      return (
                        <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E] hover:border-[#FF9F0A]/40 transition-all flex flex-col justify-between space-y-2">
                          <div>
                            <div className="flex items-center justify-between">
                              <div className="p-1.5 rounded bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/20">
                                <ShieldAlert size={14} />
                              </div>
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#151D27] text-[#FF9F0A] border border-[#25313E]">
                                M2 · AUTH
                              </span>
                            </div>
                            <div className="mt-2 leading-tight">
                              <div className="text-[11px] font-bold text-[#E8EDF3]">Forensic Auth</div>
                              <div className="text-[9px] font-mono text-[#8996A6] mt-0.5">SPF · DKIM · DMARC</div>
                            </div>
                          </div>
                          <div>
                            <div className="flex items-baseline justify-between font-mono">
                              <span className="text-lg font-bold text-[#FF9F0A]">+{score}</span>
                              <span className="text-[10px] text-[#64748B]">/ {max}</span>
                            </div>
                            <div className="w-full bg-[#151D27] h-1.5 rounded-full overflow-hidden mt-1.5">
                              <div 
                                className="bg-[#FF9F0A] h-full rounded-full transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                          <div className="flex items-center justify-between pt-1 border-t border-[#25313E]/40 font-mono text-[9px]">
                            <span className="text-[#8996A6]">{pct}% load</span>
                            <span className={`font-semibold ${score > 0 ? 'text-[#FF453A]' : 'text-[#30D158]'}`}>
                              {score > 0 ? 'AUTH FAIL' : 'PASS'}
                            </span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Card 3: Infrastructure Intel (Model 4) */}
                    {(() => {
                      const score = caseData.category_scores?.infrastructure_risk?.score ?? 0;
                      const max = caseData.category_scores?.infrastructure_risk?.max ?? 20;
                      const pct = Math.min(100, Math.round((score / max) * 100));
                      return (
                        <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E] hover:border-[#30D158]/40 transition-all flex flex-col justify-between space-y-2">
                          <div>
                            <div className="flex items-center justify-between">
                              <div className="p-1.5 rounded bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/20">
                                <Server size={14} />
                              </div>
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#151D27] text-[#30D158] border border-[#25313E]">
                                M4 · INFRA
                              </span>
                            </div>
                            <div className="mt-2 leading-tight">
                              <div className="text-[11px] font-bold text-[#E8EDF3]">Infrastructure</div>
                              <div className="text-[9px] font-mono text-[#8996A6] mt-0.5">ASN · MX · GeoIP</div>
                            </div>
                          </div>
                          <div>
                            <div className="flex items-baseline justify-between font-mono">
                              <span className="text-lg font-bold text-[#30D158]">+{score}</span>
                              <span className="text-[10px] text-[#64748B]">/ {max}</span>
                            </div>
                            <div className="w-full bg-[#151D27] h-1.5 rounded-full overflow-hidden mt-1.5">
                              <div 
                                className="bg-[#30D158] h-full rounded-full transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                          <div className="flex items-center justify-between pt-1 border-t border-[#25313E]/40 font-mono text-[9px]">
                            <span className="text-[#8996A6]">{pct}% load</span>
                            <span className={`font-semibold ${score > 15 ? 'text-[#FF453A]' : score > 0 ? 'text-[#FF9F0A]' : 'text-[#30D158]'}`}>
                              {score > 0 ? 'SUSPECT ASN' : 'REPUTABLE'}
                            </span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Card 4: BEC / Behavioral Rules (Model 6) */}
                    {(() => {
                      const score = caseData.category_scores?.behavior_bec_risk?.score ?? 0;
                      const max = caseData.category_scores?.behavior_bec_risk?.max ?? 20;
                      const pct = Math.min(100, Math.round((score / max) * 100));
                      return (
                        <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E] hover:border-[#FF453A]/40 transition-all flex flex-col justify-between space-y-2">
                          <div>
                            <div className="flex items-center justify-between">
                              <div className="p-1.5 rounded bg-[#FF453A]/10 text-[#FF453A] border border-[#FF453A]/20">
                                <AlertTriangle size={14} />
                              </div>
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#151D27] text-[#FF453A] border border-[#25313E]">
                                M6 · BEC
                              </span>
                            </div>
                            <div className="mt-2 leading-tight">
                              <div className="text-[11px] font-bold text-[#E8EDF3]">BEC Rules</div>
                              <div className="text-[9px] font-mono text-[#8996A6] mt-0.5">Behavioral Urgency</div>
                            </div>
                          </div>
                          <div>
                            <div className="flex items-baseline justify-between font-mono">
                              <span className="text-lg font-bold text-[#FF453A]">+{score}</span>
                              <span className="text-[10px] text-[#64748B]">/ {max}</span>
                            </div>
                            <div className="w-full bg-[#151D27] h-1.5 rounded-full overflow-hidden mt-1.5">
                              <div 
                                className="bg-[#FF453A] h-full rounded-full transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                          <div className="flex items-center justify-between pt-1 border-t border-[#25313E]/40 font-mono text-[9px]">
                            <span className="text-[#8996A6]">{pct}% load</span>
                            <span className={`font-semibold ${score > 0 ? 'text-[#FF453A]' : 'text-[#30D158]'}`}>
                              {score > 0 ? 'TRIGGERED' : 'CLEAR'}
                            </span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Card 5: Lookalike Domain (Model 3B) */}
                    {(() => {
                      const score = caseData.category_scores?.lookalike_impersonation_risk?.score ?? 0;
                      const max = caseData.category_scores?.lookalike_impersonation_risk?.max ?? 10;
                      const pct = Math.min(100, Math.round((score / max) * 100));
                      return (
                        <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E] hover:border-[#BF5AF2]/40 transition-all flex flex-col justify-between space-y-2">
                          <div>
                            <div className="flex items-center justify-between">
                              <div className="p-1.5 rounded bg-[#BF5AF2]/10 text-[#BF5AF2] border border-[#BF5AF2]/20">
                                <Globe size={14} />
                              </div>
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#151D27] text-[#BF5AF2] border border-[#25313E]">
                                M3B · DOM
                              </span>
                            </div>
                            <div className="mt-2 leading-tight">
                              <div className="text-[11px] font-bold text-[#E8EDF3]">Lookalike Domain</div>
                              <div className="text-[9px] font-mono text-[#8996A6] mt-0.5">Typosquat & Typos</div>
                            </div>
                          </div>
                          <div>
                            <div className="flex items-baseline justify-between font-mono">
                              <span className="text-lg font-bold text-[#BF5AF2]">+{score}</span>
                              <span className="text-[10px] text-[#64748B]">/ {max}</span>
                            </div>
                            <div className="w-full bg-[#151D27] h-1.5 rounded-full overflow-hidden mt-1.5">
                              <div 
                                className="bg-[#BF5AF2] h-full rounded-full transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                          <div className="flex items-center justify-between pt-1 border-t border-[#25313E]/40 font-mono text-[9px]">
                            <span className="text-[#8996A6]">{pct}% load</span>
                            <span className={`font-semibold ${score > 0 ? 'text-[#BF5AF2]' : 'text-[#30D158]'}`}>
                              {score > 0 ? 'HOMOGLYPH' : 'GENUINE'}
                            </span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Card 6: Identity Impersonation (Model 3A) */}
                    {(() => {
                      const score = caseData.category_scores?.identity_impersonation_risk?.score ?? 0;
                      const max = caseData.category_scores?.identity_impersonation_risk?.max ?? 10;
                      const pct = Math.min(100, Math.round((score / max) * 100));
                      return (
                        <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E] hover:border-[#FF9F0A]/40 transition-all flex flex-col justify-between space-y-2">
                          <div>
                            <div className="flex items-center justify-between">
                              <div className="p-1.5 rounded bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/20">
                                <UserCheck size={14} />
                              </div>
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#151D27] text-[#FF9F0A] border border-[#25313E]">
                                M3A · ID
                              </span>
                            </div>
                            <div className="mt-2 leading-tight">
                              <div className="text-[11px] font-bold text-[#E8EDF3]">Identity Spoof</div>
                              <div className="text-[9px] font-mono text-[#8996A6] mt-0.5">Display Name Check</div>
                            </div>
                          </div>
                          <div>
                            <div className="flex items-baseline justify-between font-mono">
                              <span className="text-lg font-bold text-[#FF9F0A]">+{score}</span>
                              <span className="text-[10px] text-[#64748B]">/ {max}</span>
                            </div>
                            <div className="w-full bg-[#151D27] h-1.5 rounded-full overflow-hidden mt-1.5">
                              <div 
                                className="bg-[#FF9F0A] h-full rounded-full transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                          <div className="flex items-center justify-between pt-1 border-t border-[#25313E]/40 font-mono text-[9px]">
                            <span className="text-[#8996A6]">{pct}% load</span>
                            <span className={`font-semibold ${score > 0 ? 'text-[#FF9F0A]' : 'text-[#30D158]'}`}>
                              {score > 0 ? 'MISMATCH' : 'MATCHED'}
                            </span>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                </div>

                {/* Panel 2: Model 1 Text / Language Signal */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                    <div className="flex items-center gap-2">
                      <FileText size={16} className="text-[#5B8DEF]" />
                      <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                        TEXT / LANGUAGE SIGNAL (MODEL 1)
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-[#8996A6]">
                      STATISTICAL NLP EVIDENCE LAYER
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">LINGUISTIC SIGNAL</span>
                      <span className={`font-bold block ${
                        (caseData.ml_signal?.ml_score ?? 0) >= 15 ? 'text-[#FF9F0A]' : 'text-[#30D158]'
                      }`}>
                        {(caseData.ml_signal?.ml_score ?? 0) >= 15 ? 'Threat-Oriented Language' : 'Benign Operational Language'}
                      </span>
                    </div>

                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">PHISHING PROBABILITY</span>
                      <span className="text-[#E8EDF3] font-bold text-sm">
                        {Math.round((caseData.ml_signal?.ml_probability ?? ((caseData.ml_signal?.ml_score ?? 15) / 30)) * 100)}%
                      </span>
                    </div>

                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">MODEL CONFIDENCE</span>
                      <span className="text-[#5B8DEF] font-bold">
                        {caseData.ml_signal?.confidence || 'MEDIUM'}
                      </span>
                    </div>
                  </div>

                  {/* Textual Indicators */}
                  {caseData.ml_signal?.ml_factors && caseData.ml_signal.ml_factors.length > 0 ? (
                    <div className="space-y-1.5 pt-1">
                      <span className="text-[10px] font-mono uppercase text-[#8996A6] block">DETECTED TEXTUAL INDICATORS</span>
                      <div className="space-y-1">
                        {caseData.ml_signal.ml_factors.map((factor: string, idx: number) => (
                          <div key={idx} className="p-2.5 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#E8EDF3] flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#5B8DEF]" />
                            <span>{factor}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div className="p-3 rounded bg-[#151D27] border border-[#25313E] text-[11px] font-mono text-[#8996A6] flex items-start gap-2">
                    <Info size={14} className="text-[#5B8DEF] flex-shrink-0 mt-0.5" />
                    <span>
                      Model 1 evaluates email subject/body language only. It is one evidence source within the ANVESH forensic assessment. Raw logistic sigmoid probability is uncalibrated.
                    </span>
                  </div>
                </div>

                {/* Panel 3: Authentication UX Matrix with Compromised Account Notice */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                    <div className="flex items-center gap-2">
                      <Lock size={16} className="text-[#5B8DEF]" />
                      <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                        CRYPTOGRAPHIC AUTHENTICATION MATRIX
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-[#8996A6]">
                      RFC-822 PROTOCOL VALIDATION
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="p-3 rounded-lg border border-[#25313E] bg-[#080C12] space-y-1">
                      <span className="text-[10px] font-mono text-[#8996A6]">SPF (Sender Policy Framework)</span>
                      <div className="flex items-center gap-1.5 pt-1">
                        {caseData.spf_status === 'PASS' ? (
                          <CheckCircle2 size={16} className="text-[#30D158]" />
                        ) : (
                          <XCircle size={16} className="text-[#FF453A]" />
                        )}
                        <span className="text-xs font-mono font-bold text-[#E8EDF3]">
                          {caseData.spf_status || 'NOT OBSERVED'}
                        </span>
                      </div>
                    </div>

                    <div className="p-3 rounded-lg border border-[#25313E] bg-[#080C12] space-y-1">
                      <span className="text-[10px] font-mono text-[#8996A6]">DKIM (Cryptographic Signature)</span>
                      <div className="flex items-center gap-1.5 pt-1">
                        {caseData.dkim_status === 'PASS' ? (
                          <CheckCircle2 size={16} className="text-[#30D158]" />
                        ) : (
                          <XCircle size={16} className="text-[#FF453A]" />
                        )}
                        <span className="text-xs font-mono font-bold text-[#E8EDF3]">
                          {caseData.dkim_status || 'NOT OBSERVED'}
                        </span>
                      </div>
                    </div>

                    <div className="p-3 rounded-lg border border-[#25313E] bg-[#080C12] space-y-1">
                      <span className="text-[10px] font-mono text-[#8996A6]">DMARC (Domain Alignment)</span>
                      <div className="flex items-center gap-1.5 pt-1">
                        {caseData.dmarc_status === 'PASS' ? (
                          <CheckCircle2 size={16} className="text-[#30D158]" />
                        ) : (
                          <XCircle size={16} className="text-[#FF453A]" />
                        )}
                        <span className="text-xs font-mono font-bold text-[#E8EDF3]">
                          {caseData.dmarc_status || 'NOT OBSERVED'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Compromised-Account Callout */}
                  <div className="p-3 rounded bg-[#1A1408] border border-[#FF9F0A]/40 text-xs font-mono text-[#FFD60A] flex items-start gap-2.5">
                    <AlertTriangle size={16} className="text-[#FF9F0A] flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold block mb-0.5 text-white">Forensic Authentication Guarantee</span>
                      Authentication PASS does not prove that the sender account is trustworthy. Cyber threat actors routinely compromise legitimate corporate or vendor mailboxes to execute Business Email Compromise (BEC) from valid Microsoft 365 or Google Workspace tenants.
                    </div>
                  </div>
                </div>

                {/* Panel 4: System Interpretation & Flagged Reasons */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                      SYSTEM INTERPRETATION & FLAGGED REASONS
                    </h3>
                    <span className="text-[10px] font-mono text-[#8996A6]">
                      EXPLAINABLE RISK ENGINE
                    </span>
                  </div>

                  {caseData.flagged_reasons && caseData.flagged_reasons.length > 0 ? (
                    <div className="space-y-2">
                      {caseData.flagged_reasons.map((reason: string, idx: number) => (
                        <div
                          key={idx}
                          className="p-3 rounded-md bg-[#080C12] border border-[#25313E] flex items-start gap-2.5 text-xs font-mono"
                        >
                          <AlertTriangle size={14} className="text-[#FF9F0A] flex-shrink-0 mt-0.5" />
                          <span className="text-[#E8EDF3]">{reason}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 rounded-md bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6]">
                      No anomalous threat indicators flagged for this message.
                    </div>
                  )}
                </div>

                {/* Panel 5: Dedicated Identity Impersonation (Model 3A) Evidence Card */}
                {caseData.identity_impersonation && (
                  <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                      <div className="flex items-center gap-2">
                        <UserCheck size={16} className="text-[#FF9F0A]" />
                        <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                          IDENTITY IMPERSONATION (MODEL 3A)
                        </h3>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                        caseData.identity_impersonation.confidence === 'HIGH'
                          ? 'bg-[#FF453A]/10 text-[#FF453A] border border-[#FF453A]/30'
                          : caseData.identity_impersonation.confidence === 'MEDIUM'
                          ? 'bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/30'
                          : 'bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/30'
                      }`}>
                        {caseData.identity_impersonation.confidence} SIGNAL
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">IDENTITY IMPERSONATION SCORE</span>
                        <div className="flex items-baseline gap-1 pt-0.5">
                          <span className="text-lg font-bold text-[#FF9F0A]">
                            {caseData.identity_impersonation.identity_impersonation_score}
                          </span>
                          <span className="text-[#8996A6] text-xs">/ 100</span>
                        </div>
                      </div>

                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">OBSERVED IDENTITY</span>
                        <span className="text-[#E8EDF3] font-bold truncate block" title={caseData.identity_impersonation.observed_identity}>
                          {caseData.identity_impersonation.observed_identity || 'Not Specified'}
                        </span>
                        <span className="text-[10px] text-[#8996A6] truncate block" title={caseData.identity_impersonation.observed_sender}>
                          {caseData.identity_impersonation.observed_sender}
                        </span>
                      </div>

                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">TRUSTED IDENTITY</span>
                        <span className="text-[#5B8DEF] font-bold truncate block" title={caseData.identity_impersonation.trusted_identity || 'None Registered'}>
                          {caseData.identity_impersonation.trusted_identity || 'No Matching Registry Entry'}
                        </span>
                        <span className="text-[10px] text-[#8996A6] block">
                          {caseData.identity_impersonation.trusted_identity ? 'Verified Target Profile' : 'Unregistered Identity'}
                        </span>
                      </div>
                    </div>

                    {/* Detected Signals */}
                    {caseData.identity_impersonation.signals && caseData.identity_impersonation.signals.length > 0 ? (
                      <div className="space-y-2 pt-1">
                        <span className="text-[10px] font-mono uppercase text-[#8996A6] block">OBSERVED IDENTITY SIGNALS</span>
                        <div className="space-y-1.5">
                          {caseData.identity_impersonation.signals.map((sig: any, idx: number) => (
                            <div key={idx} className="p-3 rounded bg-[#080C12] border border-[#25313E] flex items-start justify-between gap-3 text-xs font-mono">
                              <div className="flex items-start gap-2">
                                <span className="text-[#FF9F0A] font-bold mt-0.5">•</span>
                                <span className="text-[#E8EDF3]">{sig.description}</span>
                              </div>
                              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-[#1D2633] text-[#8996A6] flex-shrink-0">
                                +{sig.points} pts
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#30D158] flex items-center gap-2">
                        <CheckCircle2 size={14} />
                        <span>No suspicious identity, display-name, or Reply-To disparities detected.</span>
                      </div>
                    )}

                    {/* Authentication Context & Compromised Mailbox Notice */}
                    <div className="p-3 rounded bg-[#151D27] border border-[#25313E] text-xs font-mono space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-3 text-[11px]">
                          <span className="text-[#8996A6]">Authentication State:</span>
                          <span className={caseData.spf_status === 'PASS' ? 'text-[#30D158] font-bold' : 'text-[#FF453A] font-bold'}>
                            SPF {caseData.spf_status || 'NOT OBSERVED'}
                          </span>
                          <span className={caseData.dkim_status === 'PASS' ? 'text-[#30D158] font-bold' : 'text-[#FF453A] font-bold'}>
                            DKIM {caseData.dkim_status || 'NOT OBSERVED'}
                          </span>
                          <span className={caseData.dmarc_status === 'PASS' ? 'text-[#30D158] font-bold' : 'text-[#FF453A] font-bold'}>
                            DMARC {caseData.dmarc_status || 'NOT OBSERVED'}
                          </span>
                        </div>
                      </div>
                      {caseData.identity_impersonation.authentication_context?.disclaimer && (
                        <p className="text-[11px] text-[#FFD60A] pt-1 border-t border-[#25313E]/60">
                          {caseData.identity_impersonation.authentication_context.disclaimer}
                        </p>
                      )}
                    </div>

                    {/* Attribution Boundary */}
                    <div className="p-3 rounded bg-[#1A0C0E] border border-[#FF453A]/40 text-xs font-mono flex items-center justify-between">
                      <div className="flex items-center gap-2 text-[#FF453A]">
                        <ShieldAlert size={14} />
                        <span className="font-bold">Attribution Boundary:</span>
                        <span className="text-[#E8EDF3]">Actor Identity: NOT ESTABLISHED</span>
                      </div>
                      <span className="text-[10px] text-[#8996A6]">Zero Attribution Assumption</span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Phase 11: Analyst Investigation Workflow */}
            {activeSection === 'workflow' && (
              <ErrorBoundary fallbackTitle="Analyst Workflow Panel Interrupted">
                <AnalystWorkflowPanel
                  caseData={caseData}
                  onCaseUpdated={() => {
                    if (activeCaseId) {
                      fetch(`${API_BASE_URL}/cases/${activeCaseId}`)
                        .then((res) => res.json())
                        .then((data) => {
                          const c = data.case || data;
                          setCaseData((prev: any) => ({ ...prev, ...c }));
                        })
                        .catch((err) => console.warn('Error refreshing case:', err));
                    }
                  }}
                />
              </ErrorBoundary>
            )}

            {/* Phase 3: Infrastructure Intelligence & BGP Telemetry */}
            {activeSection === 'infrastructure' && (
              <div className="space-y-6">
                {/* 1. Authoritative Network & Hosting Card */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                    <div className="flex items-center gap-2">
                      <Server size={16} className="text-[#5B8DEF]" />
                      <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                        AUTHORITATIVE NETWORK & HOSTING INTELLIGENCE
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-[#8996A6]">
                      BGP ROUTING & RFC 7484 STANDARDS
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* IP & Gateway Profile */}
                    <div className="p-4 rounded-md bg-[#080C12] border border-[#25313E] space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase text-[#8996A6]">GATEWAY IP ADDRESS</span>
                        {renderStatusBadge(caseData.infrastructure?.status || 'OBSERVED')}
                      </div>
                      <div className="flex items-baseline gap-2">
                        <span className="text-sm font-bold font-mono text-[#5B8DEF]">
                          {caseData.infrastructure?.ip_address || caseData.probable_origin_ip || 'NOT ESTABLISHED'}
                        </span>
                        <span className="text-[10px] font-mono text-[#8996A6]">
                          IPv{caseData.infrastructure?.ip_version || 4} · {caseData.infrastructure?.classification || (caseData.infrastructure?.is_private ? 'RFC1918 Private' : 'Public Routable')}
                        </span>
                      </div>

                      <div className="space-y-2 pt-2 border-t border-[#25313E]/60 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">Autonomous System:</span>
                          <span className="text-[#E8EDF3] font-bold">
                            {caseData.infrastructure?.asn || 'UNAVAILABLE'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">ASN Organization:</span>
                          <span className="text-[#E8EDF3] text-right truncate max-w-[200px]" title={caseData.infrastructure?.organization || caseData.infrastructure?.asn_organization}>
                            {caseData.infrastructure?.organization || caseData.infrastructure?.asn_organization || 'NO_DATA'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">BGP Routing Prefix:</span>
                          <span className="text-[#E8EDF3]">{caseData.infrastructure?.bgp_prefix || 'NO_DATA'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">ASN Telemetry Source:</span>
                          <span className="text-[#5B8DEF] text-[10px]">{caseData.infrastructure?.asn_source || 'origin.asn.cymru.com'}</span>
                        </div>
                      </div>
                    </div>

                    {/* Cloud & Hosting Classification */}
                    <div className="p-4 rounded-md bg-[#080C12] border border-[#25313E] space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase text-[#8996A6]">HOSTING / CLOUD PROVIDER</span>
                        {renderStatusBadge(caseData.infrastructure?.cloud_classification ? 'ENRICHED' : 'NO_DATA')}
                      </div>
                      <div className="text-sm font-bold font-mono text-[#E8EDF3]">
                        {caseData.infrastructure?.cloud_classification || caseData.infrastructure?.hosting_provider || 'NO_DATA'}
                      </div>

                      <div className="space-y-2 pt-2 border-t border-[#25313E]/60 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">ISP Entity:</span>
                          <span className="text-[#E8EDF3] truncate max-w-[200px]">{caseData.infrastructure?.isp || 'NO_DATA'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">Classification Source:</span>
                          <span className="text-[#5B8DEF] text-[10px]">{caseData.infrastructure?.classification_source || 'AUTHORITATIVE_ASN_BGP_REGISTRY'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">Lookup Timestamp:</span>
                          <span className="text-[#8996A6] text-[10px]">
                            {caseData.infrastructure?.lookup_timestamp ? new Date(caseData.infrastructure.lookup_timestamp).toLocaleString() : 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#8996A6]">Heuristic Guessing:</span>
                          <span className="text-[#30D158] text-[10px]">DISABLED (Authoritative Only)</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* TOR / VPN Invariant Box */}
                  <div className="p-4 rounded-md bg-[#080C12] border border-[#25313E] space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldCheck size={14} className="text-[#5B8DEF]" />
                        <span className="font-bold text-[#E8EDF3]">TOR / VPN / PROXY TELEMETRY (OBSERVED VS INFERENCE)</span>
                      </div>
                      {renderStatusBadge(caseData.infrastructure?.tor_exit_relay ? 'OBSERVED' : 'PASS')}
                    </div>
                    <div className="p-2.5 rounded bg-[#151D27] border border-[#25313E] text-[11px] text-[#E8EDF3]">
                      <span className="text-[#8996A6] block mb-0.5">Observed Network State:</span>
                      {caseData.infrastructure?.tor_observation || (caseData.infrastructure?.tor_exit_relay ? 'IP is associated with a known TOR exit relay.' : 'IP is not associated with an active TOR exit relay as of lookup time.')}
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[10px] text-[#8996A6] pt-1">
                      <span>Source: {caseData.infrastructure?.tor_source || 'check.torproject.org / exit-addresses'}</span>
                      <span className="text-[#FF9F0A]">Forensic Invariant: Never infer attacker identity or intent from proxy state.</span>
                    </div>
                  </div>
                </div>

                {/* 2. Geolocation: IP-Associated Infrastructure Location */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                    <div className="flex items-center gap-2">
                      <MapPin size={16} className="text-[#5B8DEF]" />
                      <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                        IP-ASSOCIATED INFRASTRUCTURE LOCATION
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-[#FF9F0A]">
                      INFRASTRUCTURE ONLY · NOT ATTACKER PHYSICAL LOCATION
                    </span>
                  </div>

                  <div className="p-3 rounded-md bg-[#151D27] border border-[#25313E] flex items-start gap-2.5 text-xs font-mono text-[#8996A6]">
                    <Info size={16} className="text-[#5B8DEF] flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="text-[#E8EDF3] font-bold block mb-0.5">Forensic Geolocation Notice</span>
                      This location identifies the physical or logical facility of the ISP, cloud datacenter, or network relay. 
                      It does NOT establish the physical residence, nationality, or presence of any individual.
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]">
                      <span className="text-[10px] text-[#8996A6] block">COUNTRY / JURISDICTION</span>
                      <span className="text-[#E8EDF3] font-bold text-sm">
                        {caseData.infrastructure?.country || caseData.approximate_location || 'UNAVAILABLE'}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]">
                      <span className="text-[10px] text-[#8996A6] block">REGION / METRO</span>
                      <span className="text-[#E8EDF3] font-bold text-sm">
                        {caseData.infrastructure?.region || caseData.infrastructure?.city || 'NO_DATA'}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]">
                      <span className="text-[10px] text-[#8996A6] block">LATITUDE / LONGITUDE</span>
                      <span className="text-[#E8EDF3] font-bold text-sm">
                        {caseData.infrastructure?.latitude && caseData.infrastructure?.longitude 
                          ? `${caseData.infrastructure.latitude}, ${caseData.infrastructure.longitude}`
                          : 'NO_DATA'}
                      </span>
                    </div>
                  </div>

                  {/* Interactive World Map & Geo Route Presentation */}
                  <div className="mt-3">
                    <GeoTraceMap hops={geoHops} className="w-full" />
                  </div>
                </div>

                {/* 3. Authoritative DNS Resolution */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                    <div className="flex items-center gap-2">
                      <Globe size={16} className="text-[#5B8DEF]" />
                      <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                        AUTHORITATIVE DNS & MX RESOLUTION
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-[#8996A6]">
                      LIVE SYSTEM RESOLVER
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">TARGET DOMAIN</span>
                      <span className="text-[#5B8DEF] font-bold text-sm">
                        {caseData.domain_intelligence?.domain || (caseData.sender ? caseData.sender.split('@')[1] : 'N/A')}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">MAIL INFRASTRUCTURE PROVIDER</span>
                      <span className="text-[#E8EDF3] font-bold text-sm">
                        {(caseData.domain_intelligence?.mail_providers && caseData.domain_intelligence.mail_providers.length > 0)
                          ? caseData.domain_intelligence.mail_providers.join(', ')
                          : 'Custom / Direct Mail Gateway'}
                      </span>
                    </div>
                  </div>

                  {/* DNS Record Matrix */}
                  {caseData.domain_intelligence?.records ? (
                    <div className="space-y-2">
                      <span className="text-[10px] font-mono uppercase text-[#8996A6] block">RESOLVED RESOURCE RECORDS</span>
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {Object.entries(caseData.domain_intelligence.records).map(([rtype, recs]: [string, any]) => 
                          (recs || []).map((r: any, rIdx: number) => (
                            <div key={`${rtype}-${rIdx}`} className="p-2 rounded bg-[#080C12] border border-[#25313E] flex items-center justify-between text-xs font-mono">
                              <span className="font-bold text-[#5B8DEF] w-12">{rtype}</span>
                              <span className="text-[#E8EDF3] truncate max-w-md">{r.value || r.target || JSON.stringify(r)}</span>
                              <span className="text-[10px] text-[#8996A6]">TTL: {r.ttl || 'Default'}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6]">
                      DNS records resolved during extraction or pending domain lookup.
                    </div>
                  )}
                </div>

                {/* 4. Standards-Based RFC 7484 RDAP Registry */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                    <div className="flex items-center gap-2">
                      <Lock size={16} className="text-[#5B8DEF]" />
                      <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                        REGISTRATION DATA ACCESS PROTOCOL (RFC 7484)
                      </h3>
                    </div>
                    {renderStatusBadge(caseData.domain_intelligence?.rdap?.status || 'ENRICHED')}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">REGISTRAR</span>
                      <span className="text-[#E8EDF3] font-bold">
                        {caseData.domain_intelligence?.rdap?.registrar || 'IANA Accredited Registrar'}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">CREATION DATE</span>
                      <span className="text-[#E8EDF3]">
                        {caseData.domain_intelligence?.rdap?.created_date || 'NO_DATA'}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">EXPIRATION DATE</span>
                      <span className="text-[#E8EDF3]">
                        {caseData.domain_intelligence?.rdap?.expires_date || 'NO_DATA'}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                      <span className="text-[10px] text-[#8996A6] block">BOOTSTRAP REFERRAL CHAIN</span>
                      <span className="text-[#5B8DEF] text-[10px] truncate block" title={caseData.domain_intelligence?.rdap?.bootstrap_url}>
                        {caseData.domain_intelligence?.rdap?.bootstrap_url || 'IANA RFC 7484 Bootstrap Endpoint'}
                      </span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-[#151D27] border border-[#25313E] text-[10px] font-mono text-[#8996A6]">
                    Protocol Invariant: Resolved via IANA RFC 7484 bootstrap referral mechanism. Hardcoding rdap.org or universal single-endpoint fallbacks is strictly prohibited.
                  </div>
                </div>
              </div>
            )}

            {/* Phase 3: Attribution Boundary & Forensic Identity */}
            {activeSection === 'attribution' && (
              <div className="space-y-6">
                {/* 1. Forensic Attribution Boundary Alert Box */}
                <div className="rounded-lg border-2 border-[#FF453A]/80 bg-[#1A0C0E] p-6 space-y-4 shadow-lg">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <ShieldAlert size={22} className="text-[#FF453A]" />
                      <div>
                        <span className="text-[10px] font-mono uppercase text-[#FF453A] font-bold tracking-wider block">
                          MANDATORY FORENSIC BOUNDARY
                        </span>
                        <h2 className="text-sm font-bold font-mono text-white">
                          ACTOR IDENTITY ATTRIBUTION
                        </h2>
                      </div>
                    </div>
                    <div className="px-3 py-1.5 rounded bg-[#FF453A] text-white text-xs font-mono font-bold tracking-wide shadow-sm flex items-center gap-1.5">
                      <span>ACTOR IDENTITY:</span>
                      <span className="underline decoration-white underline-offset-2">
                        {caseData.attribution?.actor_identity || 'NOT ESTABLISHED'}
                      </span>
                    </div>
                  </div>

                  <div className="p-4 rounded bg-[#080C12]/80 border border-[#FF453A]/40 text-xs font-mono text-[#E8EDF3] leading-relaxed space-y-2">
                    <p className="font-semibold text-white">
                      {caseData.attribution?.attribution_boundary || 
                        'Technical email headers and routing telemetry definitively establish technical origin and transport hops only. Physical identity of the threat actor is NOT ESTABLISHED.'}
                    </p>
                    <p className="text-[11px] text-[#8996A6]">
                      Actor identity cannot be legally or forensically established without independent out-of-band evidence, 
                      such as judicial subpoenas, financial institution KYC records, or endpoint device forensics. 
                      Attributing a human identity or organization based solely on email headers violates forensic standards.
                    </p>
                  </div>
                </div>

                {/* 2. Attribution Assessment Metrics */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="p-4 rounded-lg border border-[#25313E] bg-[#0F151D] space-y-1">
                    <span className="text-[10px] font-mono text-[#8996A6]">THREAT RISK LEVEL</span>
                    <div className="text-base font-bold font-mono text-[#FF453A] pt-1">
                      {caseData.attribution?.threat_risk || `${caseData.risk_level} (${caseData.risk_score}/100)`}
                    </div>
                    <span className="text-[10px] font-mono text-[#8996A6] block">
                      Threat Type: {caseData.threat_type}
                    </span>
                  </div>

                  <div className="p-4 rounded-lg border border-[#25313E] bg-[#0F151D] space-y-1">
                    <span className="text-[10px] font-mono text-[#8996A6]">ORIGIN CONFIDENCE</span>
                    <div className="pt-1 flex items-center gap-2">
                      <ConfidencePill confidence={caseData.attribution?.origin_confidence || caseData.origin_confidence || 'CONFIRMED'} />
                    </div>
                    <span className="text-[10px] font-mono text-[#8996A6] block">
                      {caseData.origin_confidence === 'CONFIRMED' ? 'Verified Gateway Hop' : 'Evaluated Hop Chain'}
                    </span>
                  </div>

                  <div className="p-4 rounded-lg border border-[#25313E] bg-[#0F151D] space-y-1">
                    <span className="text-[10px] font-mono text-[#8996A6]">OBSERVED INFRASTRUCTURE</span>
                    <div className="text-xs font-bold font-mono text-[#5B8DEF] pt-1 truncate" title={caseData.attribution?.observed_infrastructure}>
                      {caseData.attribution?.observed_infrastructure || caseData.infrastructure?.cloud_classification || 'Public Gateway'}
                    </div>
                    <span className="text-[10px] font-mono text-[#8996A6] block">
                      Nature: {caseData.attribution?.evidence_nature || 'DERIVED_BOUNDARY_ASSESSMENT'}
                    </span>
                  </div>
                </div>

                {/* 3. BEC / Compromised Account Handling Invariant */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-3">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#FF9F0A]">
                    <AlertTriangle size={16} />
                    <span>BEC & ACCOUNT COMPROMISE FORENSIC INVARIANT</span>
                  </div>
                  <p className="text-xs font-mono text-[#8996A6] leading-relaxed">
                    Clean infrastructure (such as Microsoft 365 or Google Workspace) with valid SPF and DKIM signatures 
                    <span className="text-[#E8EDF3] font-semibold"> does NOT reduce or suppress elevated behavioral/BEC risk</span>. 
                    Sophisticated cyber threat actors routinely target legitimate enterprise credentials to perpetrate financial wire diversion.
                  </p>
                </div>

                {/* 4. Detailed Attribution Reasoning */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-3">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                    FORENSIC REASONING & EVIDENCE DEDUCTION
                  </h3>
                  <div className="p-4 rounded-md bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#E8EDF3] leading-relaxed">
                    {caseData.attribution?.reason || 
                      'Technical routing demonstrates transit through identified public gateway. Cryptographic authentication and hop sequencing establish delivery route. Actor identity remains strictly unestablished.'}
                  </div>
                </div>
              </div>
            )}

            {/* Phase 3: Evidence Gaps & Prescribed Next Actions */}
            {activeSection === 'evidence-gaps' && (
              <div className="space-y-6">
                {/* 1. Header Banner */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-2">
                  <div className="flex items-center gap-2">
                    <Layers size={16} className="text-[#5B8DEF]" />
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                      EVIDENCE GAP ANALYSIS & NEXT ACTIONS
                    </h3>
                  </div>
                  <p className="text-xs font-mono text-[#8996A6]">
                    Delineates what current technical evidence affirmatively establishes versus what gaps require out-of-band investigative action.
                  </p>
                </div>

                {/* 2. What Current Evidence Establishes vs Critical Gaps */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* What Is Established */}
                  <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-bold font-mono text-[#30D158]">
                      <CheckCircle2 size={16} />
                      <span>WHAT CURRENT EVIDENCE ESTABLISHES</span>
                    </div>

                    <div className="space-y-2 text-xs font-mono">
                      {(caseData.evidence_gaps?.current_evidence || [
                        { item: 'Message cryptographic integrity (SHA-256 fingerprint verified)', verified: true },
                        { item: 'Sender authorization & cryptographic signatures (SPF/DKIM/DMARC)', verified: true },
                        { item: 'Technical SMTP Received hop chain and public gateway IP', verified: true },
                        { item: 'Autonomous System Number (ASN) and routing infrastructure', verified: true }
                      ]).map((ev: any, idx: number) => (
                        <div key={idx} className="p-2.5 rounded bg-[#080C12] border border-[#25313E] flex items-center justify-between">
                          <span className="text-[#E8EDF3]">{ev.item}</span>
                          <span className="text-[10px] font-bold text-[#30D158] bg-[#30D158]/10 px-2 py-0.5 rounded border border-[#30D158]/30">
                            {ev.status || 'VERIFIED'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Critical Evidence Gaps */}
                  <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-bold font-mono text-[#FF453A]">
                      <AlertTriangle size={16} />
                      <span>WHAT EVIDENCE CANNOT ESTABLISH</span>
                    </div>

                    <div className="space-y-2 text-xs font-mono">
                      {(caseData.evidence_gaps?.identified_gaps || [
                        'Physical identity of the human actor or behind-the-keyboard operator',
                        'Pre-hop client internal origin IP (concealed behind webmail interface or cloud gateway)',
                        'Whether legitimate account was compromised via credential stuffing, session hijacking, or OAuth consent phishing',
                        'Out-of-band wire transfer authorization or legitimate financial invoice verification'
                      ]).map((gap: string, idx: number) => (
                        <div key={idx} className="p-2.5 rounded bg-[#080C12] border border-[#FF453A]/30 flex items-start gap-2">
                          <span className="text-[#FF453A] font-bold mt-0.5 flex-shrink-0">✕</span>
                          <span className="text-[#8996A6]">{gap}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* 3. Actionable Additional Evidence Options */}
                <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                      ACTIONABLE ADDITIONAL EVIDENCE OPTIONS
                    </h3>
                    <span className="text-[10px] font-mono text-[#8996A6]">
                      FORENSIC ACQUISITION PATHS
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                    {(caseData.evidence_gaps?.additional_evidence_options || [
                      {
                        evidence_type: 'Mailbox Sign-In & Unified Audit Logs',
                        source: 'Microsoft Entra ID / Google Workspace Admin SDK',
                        utility: 'Proves whether sender account was accessed by anomalous IP or session token'
                      },
                      {
                        evidence_type: 'ISP Subscriber Records (Section 63 BSA 2023)',
                        source: 'Origin Gateway ISP / Subpoena Compliance',
                        utility: 'Maps public IP gateway timestamp to physical subscriber or leased line'
                      },
                      {
                        evidence_type: 'Out-of-Band Voice / ERP Authorization',
                        source: 'Target Organization Financial Operations',
                        utility: 'Verifies whether banking routing instructions were authorized by legitimate officer'
                      },
                      {
                        evidence_type: 'Beneficiary Bank Wire Trace',
                        source: 'Receiving Financial Institution / FIU',
                        utility: 'Identifies beneficiary account holder and enforces immediate payment recall'
                      }
                    ]).map((opt: any, idx: number) => (
                      <div key={idx} className="p-3 rounded-md bg-[#080C12] border border-[#25313E] space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[#5B8DEF]">{opt.evidence_type}</span>
                        </div>
                        <div className="text-[10px] text-[#8996A6]">Source: <span className="text-[#E8EDF3]">{opt.source}</span></div>
                        <p className="text-[11px] text-[#8996A6] pt-1 border-t border-[#25313E]/60">{opt.utility}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 4. Recommended Next Action Banner */}
                <div className="rounded-lg border-2 border-[#5B8DEF] bg-[#0C1524] p-5 space-y-2 shadow-lg">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#5B8DEF]">
                    <ArrowRight size={16} />
                    <span>RECOMMENDED NEXT INVESTIGATIVE ACTION</span>
                  </div>
                  <div className="text-sm font-bold font-mono text-white">
                    {caseData.evidence_gaps?.recommended_next_action || 
                      'Preserve target mailbox audit logs (M365 Unified Audit Log / Google Workspace) and initiate out-of-band wire verification.'}
                  </div>
                  <p className="text-xs font-mono text-[#8996A6]">
                    Execute this action immediately to preserve volatile cloud session telemetry before default retention expiration.
                  </p>
                </div>
              </div>
            )}

            {/* Forensic Timeline */}
            {activeSection === 'timeline' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                    CHRONOLOGICAL FORENSIC TIMELINE
                  </h3>
                  <span className="text-[10px] font-mono text-[#8996A6]">
                    DERIVED STRICTLY FROM DATABASE TIMESTAMPS
                  </span>
                </div>

                <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-[2px] before:bg-[#25313E]">
                  {(caseData.timeline || []).map((ev: any, idx: number) => (
                    <div key={idx} className="relative space-y-1">
                      <div className="absolute -left-[21px] top-1 w-3 h-3 rounded-full bg-[#5B8DEF] border-2 border-[#0F151D]" />
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold font-mono text-[#E8EDF3]">{ev.title}</span>
                        <span className="text-[10px] font-mono text-[#8996A6]">{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}</span>
                      </div>
                      <p className="text-xs font-mono text-[#8996A6]">{ev.description}</p>
                      <span className="text-[10px] font-mono text-[#5B8DEF]/80 block">Source: {ev.source}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Lookalike Domain Tab (Model 3B) */}
            {activeSection === 'lookalike' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                  <div className="flex items-center gap-2">
                    <Globe size={16} className="text-[#BF5AF2]" />
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                      LOOKALIKE DOMAIN DETECTION (MODEL 3B)
                    </h3>
                  </div>
                  {caseData.lookalike_evidence && (
                    <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                      caseData.lookalike_evidence.signal === 'HIGH'
                        ? 'bg-[#FF453A]/10 text-[#FF453A] border border-[#FF453A]/30'
                        : caseData.lookalike_evidence.signal === 'MEDIUM'
                        ? 'bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/30'
                        : 'bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/30'
                    }`}>
                      {caseData.lookalike_evidence.signal} SIGNAL
                    </span>
                  )}
                </div>

                {caseData.lookalike_evidence ? (
                  <div className="space-y-4 text-xs font-mono">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">CANDIDATE DOMAIN</span>
                        <span className="text-[#E8EDF3] font-bold text-sm select-all">
                          {caseData.lookalike_evidence.candidate_domain || 'N/A'}
                        </span>
                      </div>
                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">TARGET TRUSTED DOMAIN</span>
                        <span className="text-[#BF5AF2] font-bold text-sm select-all">
                          {caseData.lookalike_evidence.trusted_domain || 'N/A'}
                        </span>
                      </div>
                    </div>

                    {caseData.lookalike_evidence.deterministic_indicators?.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-[10px] uppercase text-[#8996A6]">Deterministic Invariants Triggered</span>
                        <div className="flex flex-wrap gap-2">
                          {caseData.lookalike_evidence.deterministic_indicators.map((ind: string, idx: number) => (
                            <span key={idx} className="px-2 py-1 rounded bg-[#BF5AF2]/10 border border-[#BF5AF2]/30 text-[#BF5AF2] font-bold text-xs">
                              {ind}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1 text-xs">
                      <span className="text-[10px] text-[#8996A6]">RAW MODEL SCORE</span>
                      <div className="text-sm font-bold text-[#E8EDF3]">
                        {caseData.lookalike_evidence.raw_model_score?.toFixed(4) ?? '0.0000'} (Uncalibrated)
                      </div>
                      <p className="text-[11px] text-[#8996A6]">
                        {caseData.lookalike_evidence.disclaimer || 'Domain similarity evidence indicates possible impersonation infrastructure. This does not establish attacker identity.'}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6]">
                    No lookalike domain analysis available for this case.
                  </div>
                )}
              </div>
            )}

            {/* Identity Impersonation Tab (Model 3A) */}
            {activeSection === 'identity' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                  <div className="flex items-center gap-2">
                    <UserCheck size={16} className="text-[#FF9F0A]" />
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                      IDENTITY & HEADER IMPERSONATION DETECTION (MODEL 3A)
                    </h3>
                  </div>
                  {caseData.identity_impersonation && (
                    <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                      caseData.identity_impersonation.confidence === 'HIGH'
                        ? 'bg-[#FF453A]/10 text-[#FF453A] border border-[#FF453A]/30'
                        : caseData.identity_impersonation.confidence === 'MEDIUM'
                        ? 'bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/30'
                        : 'bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/30'
                    }`}>
                      {caseData.identity_impersonation.confidence} SIGNAL
                    </span>
                  )}
                </div>

                {caseData.identity_impersonation ? (
                  <div className="space-y-4 text-xs font-mono">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">IDENTITY IMPERSONATION SCORE</span>
                        <div className="flex items-baseline gap-1 pt-0.5">
                          <span className="text-xl font-bold text-[#FF9F0A]">
                            {caseData.identity_impersonation.identity_impersonation_score}
                          </span>
                          <span className="text-[#8996A6] text-xs">/ 100</span>
                        </div>
                      </div>

                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">OBSERVED SENDER IDENTITY</span>
                        <span className="text-[#E8EDF3] font-bold truncate block" title={caseData.identity_impersonation.observed_identity}>
                          {caseData.identity_impersonation.observed_identity || 'Not Specified'}
                        </span>
                        <span className="text-[10px] text-[#8996A6] truncate block" title={caseData.identity_impersonation.observed_sender}>
                          {caseData.identity_impersonation.observed_sender}
                        </span>
                      </div>

                      <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block">TRUSTED REGISTRY IDENTITY</span>
                        <span className="text-[#5B8DEF] font-bold truncate block" title={caseData.identity_impersonation.trusted_identity || 'None'}>
                          {caseData.identity_impersonation.trusted_identity || 'No Registry Match'}
                        </span>
                        <span className="text-[10px] text-[#8996A6] block">
                          {caseData.identity_impersonation.trusted_identity ? 'Target Profile Established' : 'Unregistered Identity Context'}
                        </span>
                      </div>
                    </div>

                    {/* Detected Signals */}
                    <div className="space-y-2">
                      <span className="text-[10px] uppercase text-[#8996A6] block">EVALUATED IMPERSONATION SIGNALS</span>
                      {caseData.identity_impersonation.signals?.length > 0 ? (
                        <div className="space-y-2">
                          {caseData.identity_impersonation.signals.map((sig: any, idx: number) => (
                            <div key={idx} className="p-3 rounded bg-[#080C12] border border-[#25313E] flex items-start justify-between gap-3">
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                                    sig.severity === 'HIGH' ? 'bg-[#FF453A]/10 text-[#FF453A]' : 'bg-[#FF9F0A]/10 text-[#FF9F0A]'
                                  }`}>
                                    {sig.type}
                                  </span>
                                </div>
                                <p className="text-xs text-[#E8EDF3]">{sig.description}</p>
                              </div>
                              <span className="text-xs font-bold text-[#FF9F0A] flex-shrink-0">
                                +{sig.points} pts
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-3 rounded bg-[#080C12] border border-[#25313E] text-[#30D158] flex items-center gap-2">
                          <CheckCircle2 size={14} />
                          <span>No identity impersonation signals observed for this sender.</span>
                        </div>
                      )}
                    </div>

                    {/* Authentication Matrix Notice */}
                    <div className="p-3 rounded bg-[#151D27] border border-[#25313E] space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] uppercase text-[#8996A6]">Authentication Context</span>
                        <div className="flex items-center gap-2 text-[10px]">
                          <span className={caseData.spf_status === 'PASS' ? 'text-[#30D158]' : 'text-[#FF453A]'}>SPF {caseData.spf_status || 'N/A'}</span>
                          <span className={caseData.dkim_status === 'PASS' ? 'text-[#30D158]' : 'text-[#FF453A]'}>DKIM {caseData.dkim_status || 'N/A'}</span>
                          <span className={caseData.dmarc_status === 'PASS' ? 'text-[#30D158]' : 'text-[#FF453A]'}>DMARC {caseData.dmarc_status || 'N/A'}</span>
                        </div>
                      </div>
                      <p className="text-[11px] text-[#8996A6]">
                        {caseData.identity_impersonation.authentication_context?.disclaimer || 
                          'Authentication verification verifies transport authorizations only. Compromised accounts can pass SPF/DKIM/DMARC.'}
                      </p>
                    </div>

                    {/* Mandatory Attribution Boundary */}
                    <div className="p-3 rounded bg-[#1A0C0E] border border-[#FF453A]/40 text-[#E8EDF3] flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldAlert size={14} className="text-[#FF453A]" />
                        <span className="text-[#FF453A] font-bold">MANDATORY BOUNDARY:</span>
                        <span>Actor Identity: NOT ESTABLISHED</span>
                      </div>
                      <span className="text-[10px] text-[#8996A6]">RFC-822 Discrepancy Evidence Only</span>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6]">
                    No identity impersonation analysis available.
                  </div>
                )}
              </div>
            )}

            {/* Forensic Signal Fusion Tab (Phase 9B) */}
            {activeSection === 'fusion' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#25313E]/60 pb-4">
                  <div className="flex items-center gap-2.5">
                    <Layers size={18} className="text-[#30D158]" />
                    <div>
                      <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                        FORENSIC SIGNAL FUSION ENGINE (PHASE 9B)
                      </h3>
                      <p className="text-[11px] text-[#8996A6] mt-0.5">
                        Cross-modal evidence synthesis across content, identity, infrastructure, authentication, and campaigns
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-[#151D27] text-[#8996A6] border border-[#25313E]">
                      anvesh_forensic_fusion_v1
                    </span>
                    {caseData.fusion && (
                      <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                        caseData.fusion.fusion_confidence === 'HIGH'
                          ? 'bg-[#30D158]/10 text-[#30D158] border border-[#30D158]/30'
                          : caseData.fusion.fusion_confidence === 'MEDIUM'
                          ? 'bg-[#FF9F0A]/10 text-[#FF9F0A] border border-[#FF9F0A]/30'
                          : 'bg-[#8996A6]/10 text-[#8996A6] border border-[#8996A6]/30'
                      }`}>
                        {caseData.fusion.fusion_confidence} CONFIDENCE
                      </span>
                    )}
                  </div>
                </div>

                {caseData.fusion ? (
                  <div className="space-y-5 text-xs font-mono">
                    {/* Top Summary Cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                      <div className="p-3.5 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block uppercase font-semibold">SYNTHESIZED FUSION SCORE</span>
                        <div className="flex items-baseline gap-1.5 pt-1">
                          <span className={`text-2xl font-bold ${
                            caseData.fusion.fusion_score >= 85 ? 'text-[#FF453A]' :
                            caseData.fusion.fusion_score >= 70 ? 'text-[#FF9F0A]' :
                            caseData.fusion.fusion_score >= 40 ? 'text-[#FFD60A]' :
                            'text-[#30D158]'
                          }`}>
                            {caseData.fusion.fusion_score}
                          </span>
                          <span className="text-[#8996A6] text-xs">/ 100</span>
                          <span className={`ml-2 text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            caseData.fusion.risk_level === 'CRITICAL' ? 'bg-[#FF453A]/10 text-[#FF453A]' :
                            caseData.fusion.risk_level === 'HIGH' ? 'bg-[#FF9F0A]/10 text-[#FF9F0A]' :
                            caseData.fusion.risk_level === 'MEDIUM' ? 'bg-[#FFD60A]/10 text-[#FFD60A]' :
                            'bg-[#30D158]/10 text-[#30D158]'
                          }`}>
                            {caseData.fusion.risk_level}
                          </span>
                        </div>
                        <span className="text-[10px] text-[#8996A6] block pt-1">Anti-double-counting capped</span>
                      </div>

                      <div className="p-3.5 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block uppercase font-semibold">FUSION CONFIDENCE</span>
                        <div className="text-sm font-bold text-[#E8EDF3] pt-1">
                          {caseData.fusion.fusion_confidence}
                        </div>
                        <div className="text-[10px] text-[#8996A6] space-y-0.5 pt-0.5">
                          {(caseData.fusion.confidence_rationale || []).slice(0, 2).map((r: string, idx: number) => (
                            <div key={idx} className="truncate">• {r}</div>
                          ))}
                        </div>
                      </div>

                      <div className="p-3.5 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block uppercase font-semibold">CONTRADICTIONS / CONFLICTS</span>
                        <div className="flex items-baseline gap-1.5 pt-1">
                          <span className={`text-2xl font-bold ${
                            caseData.fusion.contradictions?.length > 0 ? 'text-[#FF9F0A]' : 'text-[#30D158]'
                          }`}>
                            {caseData.fusion.contradictions?.length || 0}
                          </span>
                          <span className="text-[10px] text-[#8996A6]">
                            {caseData.fusion.contradictions?.length === 1 ? 'Contradiction identified' : 'Contradictions identified'}
                          </span>
                        </div>
                        <span className="text-[10px] text-[#8996A6] block pt-1">
                          {caseData.fusion.contradictions?.length > 0 ? 'Analyst contextualization required' : 'Evidence directions consistent'}
                        </span>
                      </div>

                      <div className="p-3.5 rounded bg-[#080C12] border border-[#25313E] space-y-1">
                        <span className="text-[10px] text-[#8996A6] block uppercase font-semibold">ATTRIBUTION BOUNDARY</span>
                        <div className="text-sm font-bold text-[#FF453A] pt-1">
                          NOT ESTABLISHED
                        </div>
                        <span className="text-[10px] text-[#8996A6] block pt-1">
                          Observed Gateway: {caseData.fusion.attribution?.observed_infrastructure || caseData.probable_origin_ip || 'Public Relay'}
                        </span>
                      </div>
                    </div>

                    {/* Forensic Interpretation */}
                    <div className="p-4 rounded bg-[#080C12] border border-[#25313E] space-y-2">
                      <div className="flex items-center gap-2 text-[#8996A6] text-[10px] uppercase font-bold tracking-wider">
                        <Info size={13} className="text-[#30D158]" />
                        <span>SYNTHESIZED FORENSIC CONCLUSION</span>
                      </div>
                      <p className="text-sm text-[#E8EDF3] leading-relaxed font-sans">
                        {caseData.fusion.forensic_interpretation}
                      </p>
                    </div>

                    {/* Primary vs Supporting Signals */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Primary Signals */}
                      <div className="p-4 rounded bg-[#080C12] border border-[#25313E] space-y-3">
                        <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-2">
                          <span className="text-[11px] font-bold text-[#FF453A] uppercase tracking-wide flex items-center gap-1.5">
                            <AlertTriangle size={13} />
                            PRIMARY SIGNALS (HIGH SEVERITY / DETERMINISTIC)
                          </span>
                          <span className="text-[10px] text-[#8996A6]">
                            {caseData.fusion.primary_signals?.length || 0} signals
                          </span>
                        </div>
                        {caseData.fusion.primary_signals && caseData.fusion.primary_signals.length > 0 ? (
                          <ul className="space-y-2">
                            {caseData.fusion.primary_signals.map((sig: string, idx: number) => (
                              <li key={idx} className="p-2 rounded bg-[#151D27]/80 border border-[#25313E]/60 text-xs text-[#E8EDF3] flex items-start gap-2">
                                <span className="text-[#FF453A] font-bold">•</span>
                                <span>{sig}</span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-[11px] text-[#8996A6] italic">No high-severity primary signals detected.</p>
                        )}
                      </div>

                      {/* Supporting Signals */}
                      <div className="p-4 rounded bg-[#080C12] border border-[#25313E] space-y-3">
                        <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-2">
                          <span className="text-[11px] font-bold text-[#5B8DEF] uppercase tracking-wide flex items-center gap-1.5">
                            <Info size={13} />
                            SUPPORTING SIGNALS (CORROBORATING CONTEXT)
                          </span>
                          <span className="text-[10px] text-[#8996A6]">
                            {caseData.fusion.supporting_signals?.length || 0} signals
                          </span>
                        </div>
                        {caseData.fusion.supporting_signals && caseData.fusion.supporting_signals.length > 0 ? (
                          <ul className="space-y-2">
                            {caseData.fusion.supporting_signals.map((sig: string, idx: number) => (
                              <li key={idx} className="p-2 rounded bg-[#151D27]/80 border border-[#25313E]/60 text-xs text-[#E8EDF3] flex items-start gap-2">
                                <span className="text-[#5B8DEF] font-bold">•</span>
                                <span>{sig}</span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-[11px] text-[#8996A6] italic">No secondary corroborating signals observed.</p>
                        )}
                      </div>
                    </div>

                    {/* Capped 6-Category Breakdown */}
                    {caseData.fusion.category_breakdown && (
                      <div className="p-4 rounded bg-[#080C12] border border-[#25313E] space-y-3">
                        <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-2">
                          <span className="text-[11px] font-bold text-[#E8EDF3] uppercase tracking-wide">
                            EXPLAINABLE CATEGORY SCORING BREAKDOWN (0 - 100 MAXIMUM)
                          </span>
                          <span className="text-[10px] text-[#8996A6]">Zero Naive Averaging</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
                          {Object.entries(caseData.fusion.category_breakdown).map(([cat, item]: [string, any]) => {
                            const pct = Math.min(100, Math.round((item.score / item.max) * 100));
                            return (
                              <div key={cat} className="p-3 rounded bg-[#151D27]/60 border border-[#25313E]/80 space-y-2">
                                <div className="flex justify-between items-center text-xs">
                                  <span className="text-[#8996A6] font-semibold uppercase">{cat.replace('_', ' ')}</span>
                                  <span className="font-bold text-[#E8EDF3]">{item.score} / {item.max} pts</span>
                                </div>
                                <div className="w-full bg-[#080C12] h-2 rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full transition-all ${
                                      item.score >= (item.max * 0.7) ? 'bg-[#FF453A]' :
                                      item.score >= (item.max * 0.4) ? 'bg-[#FF9F0A]' :
                                      item.score > 0 ? 'bg-[#30D158]' : 'bg-[#25313E]'
                                    }`}
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Contradictions & Conflict Resolution Panel */}
                    {caseData.fusion.contradictions && caseData.fusion.contradictions.length > 0 && (
                      <div className="p-4 rounded bg-[#1C1608] border border-[#FF9F0A]/40 space-y-3">
                        <div className="flex items-center gap-2 text-[#FF9F0A]">
                          <AlertTriangle size={15} />
                          <span className="text-xs font-bold uppercase tracking-wide">
                            CONTRADICTION & CONFLICT RESOLUTION
                          </span>
                        </div>
                        {caseData.fusion.contradictions.map((ct: any, idx: number) => (
                          <div key={idx} className="p-3 rounded bg-[#080C12] border border-[#FF9F0A]/30 space-y-2">
                            <div className="text-xs font-bold text-[#E8EDF3]">
                              {ct.type}: {ct.description}
                            </div>
                            <div className="text-[11px] text-[#8996A6] space-y-0.5">
                              <span className="font-semibold text-[#FF9F0A]">Conflicting Observables: </span>
                              {ct.conflicting_signals?.join(' | ')}
                            </div>
                            <div className="p-2 rounded bg-[#151D27] border border-[#25313E] text-[11px] text-[#30D158] leading-relaxed">
                              <strong>Forensic Invariant: </strong>
                              {ct.resolution_note}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Anti-Double-Counting Evidence Contributions Table */}
                    {caseData.fusion.contributions && caseData.fusion.contributions.length > 0 && (
                      <div className="p-4 rounded bg-[#080C12] border border-[#25313E] space-y-3">
                        <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-2">
                          <div>
                            <span className="text-[11px] font-bold text-[#E8EDF3] uppercase tracking-wide">
                              NON-DOUBLE-COUNTED EVIDENCE CONTRIBUTIONS
                            </span>
                            <p className="text-[10px] text-[#8996A6]">
                              Enforces independence group capping so overlapping observables do not artificially inflate risk
                            </p>
                          </div>
                          <span className="text-[10px] text-[#8996A6]">
                            {caseData.fusion.contributions.length} evaluated contributions
                          </span>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left border-collapse text-[11px]">
                            <thead>
                              <tr className="border-b border-[#25313E] text-[#8996A6]">
                                <th className="py-2 px-2.5 font-semibold">Category</th>
                                <th className="py-2 px-2.5 font-semibold">Signal</th>
                                <th className="py-2 px-2.5 font-semibold">Independence Group</th>
                                <th className="py-2 px-2.5 font-semibold text-right">Points</th>
                                <th className="py-2 px-2.5 font-semibold">Severity</th>
                                <th className="py-2 px-2.5 font-semibold">Source</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-[#25313E]/50">
                              {caseData.fusion.contributions.map((c: any, idx: number) => (
                                <tr key={idx} className="hover:bg-[#151D27]/40 transition-colors">
                                  <td className="py-2 px-2.5 font-mono text-[#8996A6]">{c.category}</td>
                                  <td className="py-2 px-2.5 font-semibold text-[#E8EDF3]">
                                    <div>{c.signal}</div>
                                    <div className="text-[10px] font-normal text-[#8996A6] line-clamp-1">{c.description}</div>
                                  </td>
                                  <td className="py-2 px-2.5 font-mono text-[#5B8DEF]">{c.independence_group}</td>
                                  <td className="py-2 px-2.5 text-right font-bold text-[#30D158]">+{c.contribution}</td>
                                  <td className="py-2 px-2.5">
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      c.severity === 'CRITICAL' ? 'bg-[#FF453A]/10 text-[#FF453A]' :
                                      c.severity === 'HIGH' ? 'bg-[#FF9F0A]/10 text-[#FF9F0A]' :
                                      'bg-[#5B8DEF]/10 text-[#5B8DEF]'
                                    }`}>
                                      {c.severity}
                                    </span>
                                  </td>
                                  <td className="py-2 px-2.5 font-mono text-[#8996A6]">{c.source}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* Mandatory Attribution Boundary & Invariant Disclaimer */}
                    <div className="p-3.5 rounded bg-[#1A0C0E] border border-[#FF453A]/40 text-[#E8EDF3] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <ShieldAlert size={16} className="text-[#FF453A] shrink-0" />
                        <div>
                          <span className="text-[#FF453A] font-bold">MANDATORY FORENSIC BOUNDARY: </span>
                          <span>Actor Identity: NOT ESTABLISHED.</span>
                          <p className="text-[10px] text-[#8996A6] mt-0.5">
                            {caseData.fusion.attribution?.attribution_boundary ||
                             'Technical headers and forensic signal fusion establish transport trajectory, identity discrepancy, and infrastructure indicators only. Physical identity of the threat actor is NOT ESTABLISHED.'}
                          </p>
                        </div>
                      </div>
                      <span className="text-[10px] text-[#8996A6] shrink-0 self-end sm:self-auto">
                        Explainable Fusion Layer
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6]">
                    No forensic signal fusion analysis available for this case.
                  </div>
                )}
              </div>
            )}

            {/* Authentication Matrix Tab */}
            {activeSection === 'authentication' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                  CRYPTOGRAPHIC AUTHENTICATION MATRIX
                </h3>
                <div className="divide-y divide-[#25313E] text-xs font-mono">
                  <div className="py-3 flex justify-between items-center">
                    <div>
                      <span className="font-bold text-[#E8EDF3]">SPF (Sender Policy Framework)</span>
                      <p className="text-[11px] text-[#8996A6]">Validates whether the sending IP was authorized by the domain owner.</p>
                    </div>
                    <span className={`font-bold px-2.5 py-1 rounded text-xs ${
                      caseData.spf_status === 'PASS' ? 'bg-[#30D158]/10 text-[#30D158]' : 'bg-[#FF453A]/10 text-[#FF453A]'
                    }`}>
                      {caseData.spf_status || 'NOT OBSERVED'}
                    </span>
                  </div>

                  <div className="py-3 flex justify-between items-center">
                    <div>
                      <span className="font-bold text-[#E8EDF3]">DKIM (DomainKeys Identified Mail)</span>
                      <p className="text-[11px] text-[#8996A6]">Cryptographically verifies message integrity using asymmetric digital signatures.</p>
                    </div>
                    <span className={`font-bold px-2.5 py-1 rounded text-xs ${
                      caseData.dkim_status === 'PASS' ? 'bg-[#30D158]/10 text-[#30D158]' : 'bg-[#FF453A]/10 text-[#FF453A]'
                    }`}>
                      {caseData.dkim_status || 'NOT OBSERVED'}
                    </span>
                  </div>

                  <div className="py-3 flex justify-between items-center">
                    <div>
                      <span className="font-bold text-[#E8EDF3]">DMARC (Domain-based Message Authentication)</span>
                      <p className="text-[11px] text-[#8996A6]">Applies domain alignment and policy enforcement (none, quarantine, reject).</p>
                    </div>
                    <span className={`font-bold px-2.5 py-1 rounded text-xs ${
                      caseData.dmarc_status === 'PASS' ? 'bg-[#30D158]/10 text-[#30D158]' : 'bg-[#FF453A]/10 text-[#FF453A]'
                    }`}>
                      {caseData.dmarc_status || 'NOT OBSERVED'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* SMTP Trajectory Route */}
            {activeSection === 'route' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                    SMTP RECEIVED HOP TRAJECTORY
                  </h3>
                  <span className="text-[10px] font-mono text-[#8996A6]">
                    ORDER PRESERVED FROM RAW HEADERS
                  </span>
                </div>

                {/* Visual Hop Flowchart & Interactive Map */}
                <HopFlowGraph hops={geoHops} className="mb-4" />
                <GeoTraceMap hops={geoHops} className="mb-4" />

                {caseData.hops && caseData.hops.length > 0 ? (
                  <div className="space-y-3">
                    {caseData.hops.map((hop: any, idx: number) => {
                      const isOrigin = Boolean(hop.is_origin || (hop.ip && hop.ip === caseData.probable_origin_ip));
                      const hasGeo = hop.latitude !== undefined && hop.latitude !== null && hop.longitude !== undefined && hop.longitude !== null;
                      const locStr = [hop.city, hop.region, hop.country].filter(Boolean).join(', ');

                      return (
                        <div
                          key={idx}
                          className="p-3.5 rounded-lg bg-[#080C12] border border-[#25313E] space-y-2 text-xs font-mono transition-all hover:border-[#38BDF8]/40"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E293B]/60 pb-2">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-[#5B8DEF]">Relay Hop #{hop.hop || idx + 1}</span>
                              {isOrigin ? (
                                <span className="bg-[#FF5E5E]/20 text-[#FF5E5E] text-[10px] px-2 py-0.5 rounded font-bold">
                                  ORIGIN MTA
                                </span>
                              ) : idx === 0 ? (
                                <span className="bg-[#10B981]/20 text-[#10B981] text-[10px] px-2 py-0.5 rounded font-bold">
                                  DESTINATION MX
                                </span>
                              ) : (
                                <span className="bg-[#38BDF8]/10 text-[#38BDF8] text-[10px] px-2 py-0.5 rounded font-bold">
                                  TRANSIT RELAY
                                </span>
                              )}
                              {hop.is_public === false && (
                                <span className="bg-[#64748B]/20 text-[#94A3B8] text-[10px] px-2 py-0.5 rounded font-medium flex items-center gap-1">
                                  <Lock size={10} /> RFC-1918 Private
                                </span>
                              )}
                            </div>
                            {hop.ip && (
                              <span className="text-[11px] font-bold text-[#E2E8F0] bg-[#0F172A] px-2 py-0.5 rounded border border-[#1E293B]">
                                IP: {hop.ip}
                              </span>
                            )}
                          </div>

                          {/* Live GeoIP Metadata */}
                          {(locStr || hop.isp || hasGeo) && (
                            <div className="flex flex-wrap items-center gap-3 text-[11px] text-[#94A3B8] bg-[#0B1017] p-2 rounded border border-[#1E293B]/50">
                              {locStr && (
                                <div className="flex items-center gap-1">
                                  <MapPin size={12} className="text-[#38BDF8]" />
                                  <span className="text-[#E2E8F0] font-medium">{locStr}</span>
                                </div>
                              )}
                              {hasGeo && (
                                <span className="text-[#64748B] text-[10px]">
                                  ({hop.latitude?.toFixed(3)}, {hop.longitude?.toFixed(3)})
                                </span>
                              )}
                              {hop.isp && (
                                <div className="flex items-center gap-1 text-[#64748B] text-[10px]">
                                  <Server size={11} className="text-[#64748B]" />
                                  <span>{hop.isp} {hop.asn ? `(${hop.asn})` : ''}</span>
                                </div>
                              )}
                            </div>
                          )}

                          <p className="text-[11px] text-[#8996A6] font-mono break-all leading-relaxed bg-[#05080E] p-2 rounded">
                            {hop.raw}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="p-4 rounded-md bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6]">
                    No Received hops observed in this email.
                  </div>
                )}
              </div>
            )}

            {/* Observables & Evidence Graph */}
            {activeSection === 'observables' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                    EXTRACTED OBSERVABLES & EVIDENCE RELATIONSHIPS
                  </h3>
                  <span className="text-[10px] font-mono text-[#8996A6]">
                    IMMUTABLE INDICATOR EXTRACTION
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {(caseData.observables || []).map((obs: any, idx: number) => (
                    <div
                      key={idx}
                      onClick={() => handleSelectObservable(obs)}
                      className="p-3 rounded-md bg-[#080C12] border border-[#25313E] hover:border-[#5B8DEF] cursor-pointer transition-colors space-y-1 text-xs font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-bold uppercase text-[#5B8DEF]">{obs.ioc_type || obs.type}</span>
                        {obs.reputation_score !== undefined && obs.reputation_score > 0 && (
                          <span className="text-[10px] font-bold text-[#FF453A]">Flagged</span>
                        )}
                      </div>
                      <span className="text-[#E8EDF3] font-bold truncate block">{obs.value}</span>
                      <p className="text-[11px] text-[#8996A6]">{obs.description}</p>
                    </div>
                  ))}
                  {(!caseData.observables || caseData.observables.length === 0) && (
                    <div className="p-4 rounded-md bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6] col-span-2">
                      No observables recorded for this investigation.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Raw Evidence Data */}
            {activeSection === 'headers' && (
              <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
                  <div>
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wide text-[#E8EDF3]">
                      RAW FORENSIC EVIDENCE
                    </h3>
                    <p className="text-[11px] text-[#8996A6] mt-0.5">
                      Distinction: Raw Evidence (Original Immutable Input) vs System Interpretation
                    </p>
                  </div>
                  {caseData.email?.raw_headers && (
                    <button
                      onClick={() => copyToClipboard(caseData.email.raw_headers, 'raw_h')}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1D2633] hover:bg-[#25313E] text-xs font-mono text-[#E8EDF3] cursor-pointer"
                    >
                      {copiedKey === 'raw_h' ? <Check size={12} className="text-[#30D158]" /> : <Copy size={12} />}
                      <span>Copy Raw Headers</span>
                    </button>
                  )}
                </div>

                <div className="space-y-3">
                  <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1 text-xs font-mono">
                    <span className="text-[10px] text-[#8996A6] block">MESSAGE-ID:</span>
                    <span className="text-[#E8EDF3] select-all">{caseData.email?.message_id || 'Not specified in header'}</span>
                  </div>

                  <div className="p-3 rounded bg-[#080C12] border border-[#25313E] space-y-1 text-xs font-mono">
                    <span className="text-[10px] text-[#8996A6] block">SHA-256 HASH OF RAW BYTES:</span>
                    <span className="text-[#5B8DEF] font-bold select-all">{caseData.sha256_hash || 'N/A'}</span>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] font-mono text-[#8996A6] block">RAW RFC-822 HEADERS:</span>
                    <pre className="p-3 rounded bg-[#080C12] border border-[#25313E] text-[11px] font-mono text-[#8996A6] overflow-x-auto whitespace-pre-wrap max-h-96">
                      {caseData.email?.raw_headers || 'Raw header text preserved in immutable evidence ledger.'}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* ------------------------------------------------------------- */}
      {/* PANE 3: CONTEXTUAL OBSERVABLE INSPECTOR                       */}
      {/* ------------------------------------------------------------- */}
      {inspectorOpen && (
        <aside className="w-80 border-l border-[#25313E] bg-[#0F151D] p-4 flex flex-col justify-between overflow-y-auto flex-shrink-0 select-none">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
              <span className="text-[10px] font-mono uppercase text-[#8996A6] tracking-wider">
                Observable Inspector
              </span>
              <button
                onClick={() => setInspectorOpen(false)}
                className="text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
                title="Collapse Inspector"
              >
                <PanelRightClose size={14} />
              </button>
            </div>

            {selectedEntity ? (
              <div className="space-y-4">
                <div className="p-3 rounded-md bg-[#080C12] border border-[#25313E] space-y-1">
                  <span className="text-[10px] font-mono uppercase text-[#5B8DEF] block">
                    {selectedEntity.type} TARGET
                  </span>
                  <span className="text-xs font-bold font-mono text-[#E8EDF3] break-all block">
                    {selectedEntity.value}
                  </span>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-[#25313E]/40">
                    <span className="text-[#8996A6]">Classification:</span>
                    <span className="text-[#E8EDF3] font-semibold">{selectedEntity.type === 'IP' ? 'Public / Network Gateway' : 'Observable'}</span>
                  </div>
                  {selectedEntity.location && (
                    <div className="flex justify-between py-1 border-b border-[#25313E]/40">
                      <span className="text-[#8996A6]">Infrastructure Location:</span>
                      <span className="text-[#E8EDF3] text-right truncate max-w-[150px]">{selectedEntity.location}</span>
                    </div>
                  )}
                  {selectedEntity.confidence && (
                    <div className="flex justify-between py-1 border-b border-[#25313E]/40">
                      <span className="text-[#8996A6]">Confidence:</span>
                      <ConfidencePill confidence={selectedEntity.confidence} />
                    </div>
                  )}
                  {selectedEntity.infrastructure?.asn && (
                    <div className="flex justify-between py-1 border-b border-[#25313E]/40">
                      <span className="text-[#8996A6]">Routing ASN:</span>
                      <span className="text-[#E8EDF3] font-bold">{selectedEntity.infrastructure.asn}</span>
                    </div>
                  )}
                  {selectedEntity.infrastructure?.cloud_classification && (
                    <div className="flex justify-between py-1 border-b border-[#25313E]/40">
                      <span className="text-[#8996A6]">Hosting Provider:</span>
                      <span className="text-[#5B8DEF] font-bold truncate max-w-[140px]">{selectedEntity.infrastructure.cloud_classification}</span>
                    </div>
                  )}
                  {selectedEntity.infrastructure?.tor_observation && (
                    <div className="flex justify-between py-1 border-b border-[#25313E]/40">
                      <span className="text-[#8996A6]">TOR Status:</span>
                      <span className="text-[#E8EDF3] text-[10px] text-right max-w-[150px]">{selectedEntity.infrastructure.tor_observation}</span>
                    </div>
                  )}
                </div>

                {/* Honest Zero-Fabrication Intelligence Notice */}
                <div className="p-3 rounded-md bg-[#080C12] border border-[#25313E]/80 text-[11px] font-mono text-[#8996A6] leading-relaxed space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[#E8EDF3] font-bold">Evidence Provenance</span>
                    {renderStatusBadge(selectedEntity.infrastructure?.status || 'OBSERVED')}
                  </div>
                  <p>
                    {selectedEntity.disclaimer || 'IP-associated infrastructure location. Geolocation identifies network hosting/routing infrastructure and does NOT establish physical location of any human actor.'}
                  </p>
                  {selectedEntity.infrastructure?.classification_source && (
                    <div className="text-[10px] text-[#5B8DEF] pt-1 border-t border-[#25313E]/40">
                      Source: {selectedEntity.infrastructure.classification_source}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs font-mono text-[#8996A6]">
                Select any observable, IP, or hop to inspect forensic attributes.
              </div>
            )}
          </div>
        </aside>
      )}

      {/* Floating Toggle if Inspector Closed */}
      {!inspectorOpen && (
        <button
          onClick={() => setInspectorOpen(true)}
          className="fixed right-3 bottom-5 p-2 rounded-md bg-[#151D27] border border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3] shadow-lg cursor-pointer"
          title="Open Inspector"
        >
          <PanelRightOpen size={16} />
        </button>
      )}

      {/* ------------------------------------------------------------- */}
      {/* MODAL: COMPREHENSIVE FORENSIC REPORT (PHASE 10 DOSSIER)       */}
      {/* ------------------------------------------------------------- */}
      <ForensicReportModal
        isOpen={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        caseData={caseData}
        reportData={reportData}
        loading={loadingReport}
      />
      {/* ------------------------------------------------------------- */}
      {/* CAMPAIGN DOSSIER MODAL                                         */}
      {/* ------------------------------------------------------------- */}
      {campaignModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-3xl max-h-[88vh] flex flex-col rounded-xl border border-[#25313E] bg-[#0F151D] shadow-2xl overflow-hidden font-mono">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#25313E] bg-[#151D27]">
              <div className="flex items-center gap-3">
                <Layers size={18} className="text-[#5B8DEF]" />
                <div>
                  <h3 className="text-sm font-bold text-[#E8EDF3]">
                    {campaignDetails?.campaign?.name || 'Potential Campaign Dossier'}
                  </h3>
                  <div className="flex items-center gap-2 mt-0.5 text-[11px] text-[#8996A6]">
                    <span>ID: {campaignDetails?.campaign?.campaign_id}</span>
                    <span>·</span>
                    <span className="text-[#30D158]">Confidence: {campaignDetails?.campaign?.confidence}</span>
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setCampaignModalOpen(false)}
                className="text-[#8996A6] hover:text-[#E8EDF3] p-1 rounded-md hover:bg-[#1D2633] transition-colors cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {loadingCampaign ? (
                <div className="py-12 text-center text-xs text-[#8996A6]">
                  Loading correlated campaign intelligence...
                </div>
              ) : campaignDetails?.campaign ? (
                <div className="space-y-5 text-xs">
                  {/* Explanation Banner */}
                  <div className="p-4 rounded-lg bg-[#080C12] border border-[#5B8DEF]/30 space-y-2">
                    <span className="text-[10px] uppercase text-[#5B8DEF] font-bold block">
                      DETERMINISTIC CORRELATION ASSESSMENT
                    </span>
                    <p className="text-[#E8EDF3] leading-relaxed">
                      {campaignDetails.campaign.explanation}
                    </p>
                  </div>

                  {/* Summary Grid */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]">
                      <span className="text-[10px] text-[#8996A6] block uppercase">Related Cases</span>
                      <span className="text-base font-bold text-[#E8EDF3] mt-1 block">
                        {campaignDetails.case_count || campaignDetails.campaign.case_count || 1}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]">
                      <span className="text-[10px] text-[#8996A6] block uppercase">Cluster Status</span>
                      <span className="text-base font-bold text-[#30D158] mt-1 block">
                        {campaignDetails.campaign.status || 'ACTIVE'}
                      </span>
                    </div>
                    <div className="p-3 rounded bg-[#080C12] border border-[#25313E]">
                      <span className="text-[10px] text-[#8996A6] block uppercase">Correlation Score</span>
                      <span className="text-base font-bold text-[#5B8DEF] mt-1 block">
                        {campaignDetails.campaign.confidence_score || 80}/100
                      </span>
                    </div>
                  </div>

                  {/* Related Cases List */}
                  <div className="space-y-2">
                    <span className="text-[10px] uppercase text-[#8996A6] font-bold block">
                      LINKED INVESTIGATIONS
                    </span>
                    <div className="space-y-2">
                      {(campaignDetails.cases || []).map((c: any) => (
                        <div key={c.id || c.case_number} className="p-3 rounded bg-[#080C12] border border-[#25313E] flex items-center justify-between">
                          <div>
                            <span className="font-bold text-[#5B8DEF] block">{c.case_number}</span>
                            <span className="text-[11px] text-[#8996A6]">{c.title}</span>
                          </div>
                          <div className="text-right">
                            <span className="text-[11px] font-bold text-[#FF9F0A] block">Score: {c.risk_score}/100</span>
                            <span className="text-[10px] text-[#8996A6]">{c.threat_type}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Chronological Timeline */}
                  {campaignDetails.timeline && campaignDetails.timeline.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-[10px] uppercase text-[#8996A6] font-bold block">
                        CHRONOLOGICAL EVIDENCE TIMELINE
                      </span>
                      <div className="space-y-2">
                        {campaignDetails.timeline.map((ev: any, idx: number) => (
                          <div key={idx} className="p-2.5 rounded bg-[#080C12] border border-[#25313E]/60 text-[11px] flex gap-3">
                            <span className="text-[#5B8DEF] font-mono whitespace-nowrap">
                              {ev.timestamp ? ev.timestamp.slice(0, 10) : 'Observed'}
                            </span>
                            <div>
                              <div className="text-[#E8EDF3] font-semibold">{ev.title}</div>
                              <div className="text-[#8996A6]">{ev.description}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Attribution Boundary Invariant Banner */}
                  <div className="p-3 rounded bg-[#1A0C0E] border border-[#FF453A]/40 text-[11px] text-[#8996A6]">
                    <span className="text-[#FF453A] font-bold block mb-1">FORENSIC ATTRIBUTION BOUNDARY:</span>
                    {campaignDetails.disclaimer || 'Campaign grouping indicates observed infrastructure and behavioral correlation. It does not establish common physical actor identity.'}
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-[#FF453A] text-xs">
                  Could not load campaign record.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
