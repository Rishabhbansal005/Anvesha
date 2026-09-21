/**
 * ANVESH Phase 8B — Campaign Investigation Experience
 * Professional Forensic Split-Layout: List+Timeline | Graph | Evidence
 * Design: Clean, calm, authoritative forensic workstation.
 */
import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Layers, ChevronRight, X, Clock, Network, AlertTriangle, Info,
  RefreshCw, ChevronDown, ChevronUp, Minus, Plus,
} from 'lucide-react';
import { API_BASE_URL } from '../constants';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Campaign {
  id: string; campaign_id: string; name: string; status: string;
  confidence: string; confidence_score: number; description?: string;
  explanation?: string; first_observed_at?: string; last_observed_at?: string;
  case_count?: number;
}
interface GraphNode { id: string; type: string; label: string; x?: number; y?: number; }
interface GraphEdge { source: string; target: string; relation: string; strength: string; }
interface GraphSummary {
  total_nodes: number; total_edges: number; cases_count: number;
  domains: string[]; ips: string[]; urls: string[]; reply_tos: string[]; senders: string[];
}
interface GraphData { nodes: GraphNode[]; edges: GraphEdge[]; summary: GraphSummary; }
interface TimelineEvent { id: string; event_type: string; timestamp?: string; title: string; description: string; }
interface CampaignDetail {
  campaign: Campaign; cases: any[]; case_count: number; timeline: TimelineEvent[];
  observables_summary: any; disclaimer: string;
}

// ── Constants ──────────────────────────────────────────────────────────────────
const NODE_COLORS: Record<string, string> = {
  CAMPAIGN: '#5B8DEF', CASE: '#35C98A', EMAIL: '#9B8DEF', DOMAIN: '#F2B84B',
  IP: '#EF6262', URL: '#E8A04B', REPLY_TO: '#EF8262', SENDER: '#8996A6',
};
const NODE_RADII: Record<string, number> = {
  CAMPAIGN: 28, CASE: 22, EMAIL: 16, DOMAIN: 14, IP: 14, URL: 12, REPLY_TO: 12, SENDER: 12,
};
const EDGE_LABELS: Record<string, string> = {
  INCLUDES_CASE: 'includes', INGESTED_EMAIL: 'email', OBSERVED_DOMAIN: 'domain',
  OBSERVED_IP: 'IP', OBSERVED_URL: 'URL', SPECIFIES_REPLY_TO: 'reply-to', HAS_SENDER: 'sender',
};
const EVENT_LABELS: Record<string, string> = {
  CASE_REGISTERED: 'Case Registered', IP_OBSERVED: 'IP Observed',
  REPLY_TO_OBSERVED: 'Reply-To Observed', CAMPAIGN_CREATED: 'Campaign Created', CAMPAIGN_UPDATED: 'Campaign Updated',
};
const EMPTY_G: GraphData = {
  nodes: [], edges: [],
  summary: { total_nodes: 0, total_edges: 0, cases_count: 0, domains: [], ips: [], urls: [], reply_tos: [], senders: [] },
};

// ── Helpers ────────────────────────────────────────────────────────────────────
function fmtDate(s?: string) {
  if (!s) return '--';
  try { return new Date(s).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); }
  catch { return s.slice(0, 10); }
}
function fmtDT(s?: string) {
  if (!s) return '--';
  try {
    const d = new Date(s);
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
      + ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  } catch { return s.slice(0, 16).replace('T', ' '); }
}
function confClass(c?: string) {
  switch ((c || '').toUpperCase()) {
    case 'HIGH':   return 'bg-[#35C98A]/15 text-[#35C98A] border border-[#35C98A]/30';
    case 'MEDIUM': return 'bg-[#F2B84B]/15 text-[#F2B84B] border border-[#F2B84B]/30';
    case 'LOW':    return 'bg-[#EF6262]/15 text-[#EF6262] border border-[#EF6262]/30';
    default:       return 'bg-[#25313E]/50 text-[#8996A6] border border-[#25313E]';
  }
}
function statusDot(s?: string) {
  switch ((s || '').toUpperCase()) {
    case 'ACTIVE': return 'bg-[#35C98A]';
    case 'REVIEW': return 'bg-[#F2B84B]';
    case 'CLOSED': return 'bg-[#8996A6]';
    default: return 'bg-[#5B8DEF]';
  }
}

// ── Layout ─────────────────────────────────────────────────────────────────────
function computeLayout(nodes: GraphNode[], edges: GraphEdge[], w: number, h: number): GraphNode[] {
  if (!nodes.length) return nodes;
  const cx = w / 2, cy = h / 2;
  const byType: Record<string, string[]> = {};
  nodes.forEach(n => { (byType[n.type] = byType[n.type] || []).push(n.id); });
  const placed: Record<string, { x: number; y: number }> = {};
  (byType['CAMPAIGN'] || []).forEach(id => { placed[id] = { x: cx, y: cy }; });
  const cIds = byType['CASE'] || [];
  const cR = Math.min(125, Math.max(80, cIds.length * 38));
  cIds.forEach((id, i) => {
    const a = (2 * Math.PI * i / Math.max(cIds.length, 1)) - Math.PI / 2;
    placed[id] = { x: cx + cR * Math.cos(a), y: cy + cR * Math.sin(a) };
  });
  (byType['EMAIL'] || []).forEach((id, i) => {
    const pe = edges.find(e => e.target === id && e.relation === 'INGESTED_EMAIL');
    const par = pe ? placed[pe.source] : { x: cx, y: cy };
    const a = (2 * Math.PI * i / Math.max((byType['EMAIL'] || []).length, 1));
    placed[id] = { x: (par?.x ?? cx) + 52 * Math.cos(a), y: (par?.y ?? cy) + 52 * Math.sin(a) };
  });
  const outer: string[] = [];
  ['SENDER', 'REPLY_TO', 'DOMAIN', 'IP', 'URL'].forEach(t => (byType[t] || []).forEach(id => outer.push(id)));
  const oR = Math.min(w * 0.38, Math.max(165, outer.length * 24));
  outer.forEach((id, i) => {
    const a = (2 * Math.PI * i / Math.max(outer.length, 1)) + Math.PI / 5;
    placed[id] = { x: cx + oR * Math.cos(a), y: cy + oR * Math.sin(a) };
  });
  return nodes.map(n => ({ ...n, x: placed[n.id]?.x ?? cx, y: placed[n.id]?.y ?? cy }));
}


// ── Graph ──────────────────────────────────────────────────────────────────────
interface GraphProps { data: GraphData; selectedNodeId: string | null; onSelectNode: (n: GraphNode | null) => void; }

const CampaignGraph: React.FC<GraphProps> = ({ data, selectedNodeId, onSelectNode }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ w: 600, h: 460 });
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const drag = useRef({ active: false, sx: 0, sy: 0 });

  useEffect(() => {
    if (!containerRef.current) return;
    const obs = new ResizeObserver(([e]) => { if (e) setDims({ w: e.contentRect.width, h: e.contentRect.height }); });
    obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, []);

  const laidOut = useMemo(() => computeLayout(data.nodes, data.edges, dims.w, dims.h), [data.nodes, data.edges, dims]);
  const nodeMap = useMemo(() => { const m: Record<string, GraphNode> = {}; laidOut.forEach(n => (m[n.id] = n)); return m; }, [laidOut]);

  if (!data.nodes.length) return (
    <div className="flex-1 flex items-center justify-center text-xs text-[#4B5968]">
      <div className="text-center space-y-2">
        <Network size={32} className="mx-auto text-[#1D2633]" />
        <p>No relationships available for this campaign.</p>
        <p className="text-[10px]">Graph emerges when cases share infrastructure.</p>
      </div>
    </div>
  );

  return (
    <div ref={containerRef} className="relative flex-1 overflow-hidden" style={{ cursor: drag.current.active ? 'grabbing' : 'grab' }}>
      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
        <button onClick={() => setZoom(z => Math.min(3, z + 0.25))} className="w-7 h-7 rounded bg-[#0F151D] border border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3] flex items-center justify-center transition-colors"><Plus size={11} /></button>
        <button onClick={() => setZoom(z => Math.max(0.25, z - 0.25))} className="w-7 h-7 rounded bg-[#0F151D] border border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3] flex items-center justify-center transition-colors"><Minus size={11} /></button>
        <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }} title="Reset view" className="w-7 h-7 rounded bg-[#0F151D] border border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3] flex items-center justify-center transition-colors"><RefreshCw size={10} /></button>
      </div>
      <svg width="100%" height="100%"
        onWheel={e => { e.preventDefault(); setZoom(z => Math.min(3, Math.max(0.25, z - e.deltaY * 0.001))); }}
        onMouseDown={e => { if ((e.target as Element).closest('circle')) return; drag.current = { active: true, sx: e.clientX - pan.x, sy: e.clientY - pan.y }; }}
        onMouseMove={e => { if (!drag.current.active) return; setPan({ x: e.clientX - drag.current.sx, y: e.clientY - drag.current.sy }); }}
        onMouseUp={() => { drag.current.active = false; }}
        onMouseLeave={() => { drag.current.active = false; }}
        onClick={() => onSelectNode(null)}>
        <defs>
          <marker id="a8b" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#2A3A4E" />
          </marker>
        </defs>
        <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
          {data.edges.map((edge, i) => {
            const s = nodeMap[edge.source], t = nodeMap[edge.target];
            if (!s || !t) return null;
            const dx = t.x! - s.x!, dy = t.y! - s.y!, dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const nx = dx / dist, ny = dy / dist;
            const sr = NODE_RADII[s.type] || 14, tr = NODE_RADII[t.type] || 14;
            const hl = selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId);
            return (
              <g key={i}>
                <line x1={s.x! + nx * sr} y1={s.y! + ny * sr} x2={t.x! - nx * (tr + 5)} y2={t.y! - ny * (tr + 5)}
                  stroke={hl ? '#5B8DEF' : '#1D2B3A'} strokeWidth={hl ? 1.5 : 1}
                  strokeDasharray={edge.strength === 'WEAK' ? '4,4' : undefined}
                  markerEnd="url(#a8b)" opacity={selectedNodeId && !hl ? 0.1 : 0.75} />
                {hl && <text x={(s.x! + t.x!) / 2} y={(s.y! + t.y!) / 2 - 5} textAnchor="middle" fontSize="8" fill="#5B8DEF" fontFamily="monospace" opacity={0.85}>{EDGE_LABELS[edge.relation] || edge.relation}</text>}
              </g>
            );
          })}
          {laidOut.map(node => {
            const color = NODE_COLORS[node.type] || '#8996A6';
            const r = NODE_RADII[node.type] || 14;
            const isSel = node.id === selectedNodeId;
            const isHl = !selectedNodeId || isSel
              || data.edges.some(e => (e.source === selectedNodeId && e.target === node.id) || (e.target === selectedNodeId && e.source === node.id));
            return (
              <g key={node.id} transform={`translate(${node.x},${node.y})`} style={{ cursor: 'pointer' }} opacity={isHl ? 1 : 0.18}
                onClick={e => { e.stopPropagation(); onSelectNode(isSel ? null : node); }}>
                {isSel && <circle r={r + 7} fill="none" stroke={color} strokeWidth={1.5} opacity={0.28} />}
                <circle r={r} fill={color + '15'} stroke={isSel ? color : color + '45'} strokeWidth={isSel ? 2 : 1.5} />
                <text y={-r - 5} textAnchor="middle" fontSize="7" fill={color} fontFamily="monospace" opacity={0.6} style={{ pointerEvents: 'none' }}>{node.type}</text>
                <text y={r + 14} textAnchor="middle" fontSize="8.5" fill={isSel ? color : '#6B7A8D'} fontFamily="monospace" fontWeight={isSel ? 'bold' : 'normal'} style={{ pointerEvents: 'none' }}>
                  {node.label.length > 18 ? node.label.slice(0, 16) + '\u2026' : node.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
};

// ── Campaign List Item ─────────────────────────────────────────────────────────
const CampaignListItem: React.FC<{ campaign: Campaign; isSelected: boolean; onClick: () => void }> = ({ campaign, isSelected, onClick }) => (
  <button onClick={onClick}
    className={`w-full text-left px-4 py-3 border-b border-[#0E1620] hover:bg-[#0F151D] transition-colors group border-l-2 ${isSelected ? 'bg-[#0F151D] border-l-[#5B8DEF]' : 'border-l-transparent'}`}>
    <div className="flex items-start justify-between gap-2">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${statusDot(campaign.status)}`} />
          <span className="text-[9px] font-mono text-[#3A4A5C] truncate">{campaign.campaign_id}</span>
        </div>
        <p className="text-[11px] font-semibold text-[#C8D3DF] leading-tight line-clamp-2 group-hover:text-[#E8EDF3]">{campaign.name}</p>
        <div className="flex items-center gap-2 mt-1.5">
          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${confClass(campaign.confidence)}`}>{campaign.confidence || 'LOW'}</span>
          <span className="text-[9px] text-[#3A4A5C] font-mono">{campaign.case_count ?? 0} case{(campaign.case_count ?? 0) !== 1 ? 's' : ''}</span>
        </div>
      </div>
      <ChevronRight size={13} className={`flex-shrink-0 mt-1 transition-colors ${isSelected ? 'text-[#5B8DEF]' : 'text-[#1D2633] group-hover:text-[#8996A6]'}`} />
    </div>
  </button>
);

// ── Timeline ───────────────────────────────────────────────────────────────────
const TimelinePanel: React.FC<{ events: TimelineEvent[]; loading: boolean }> = ({ events, loading }) => {
  if (loading) return <div className="py-6 flex justify-center"><RefreshCw size={14} className="animate-spin text-[#5B8DEF]" /></div>;
  if (!events.length) return (
    <div className="py-6 px-4 text-center text-[10px] text-[#3A4A5C]">
      <Clock size={14} className="mx-auto mb-2 text-[#1D2633]" />No timeline events.
    </div>
  );
  return (
    <div className="flex-1 overflow-y-auto px-4 py-3">
      <div className="relative">
        <div className="absolute left-[5px] top-2 bottom-2 w-px bg-[#1D2633]" />
        <div className="space-y-3">
          {events.map((ev, idx) => (
            <div key={ev.id || idx} className="relative pl-5">
              <div className={`absolute left-0 top-[5px] w-2.5 h-2.5 rounded-full border-2 border-[#080C12] z-10 ${idx === 0 ? 'bg-[#5B8DEF]' : idx === events.length - 1 ? 'bg-[#35C98A]' : 'bg-[#1D2633]'}`} />
              <div className="text-[8px] font-mono text-[#3A4A5C] mb-0.5">{fmtDT(ev.timestamp)}</div>
              <div className="text-[8px] font-bold text-[#4B5968] uppercase tracking-wide mb-0.5">{EVENT_LABELS[ev.event_type] || ev.event_type}</div>
              <p className="text-[10px] font-semibold text-[#C8D3DF] leading-tight">{ev.title}</p>
              {ev.description && <p className="text-[9px] text-[#3A4A5C] mt-0.5 leading-relaxed line-clamp-2">{ev.description}</p>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ── Shared Components ──────────────────────────────────────────────────────────
const SLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span className="text-[9px] uppercase font-bold text-[#4B5968] tracking-wider block">{children}</span>
);
const FRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="flex items-baseline justify-between gap-2 py-0.5">
    <span className="text-[10px] text-[#3A4A5C] flex-shrink-0">{label}</span>
    <span className="text-[10px] font-mono text-[#C8D3DF] text-right">{value}</span>
  </div>
);
const SCell: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="p-2.5 rounded bg-[#080C12] border border-[#1D2633]">
    <span className="text-[9px] text-[#3A4A5C] uppercase block">{label}</span>
    <span className="text-sm font-bold text-[#E8EDF3] font-mono mt-0.5 block">{value}</span>
  </div>
);
const ColSec: React.FC<{ label: string; open: boolean; onToggle: () => void; children: React.ReactNode }> = ({ label, open, onToggle, children }) => (
  <div className="rounded-lg border border-[#1D2633] bg-[#0C1420] overflow-hidden">
    <button onClick={onToggle} className="w-full flex items-center justify-between px-3 py-2.5 text-left hover:bg-[#0F151D] transition-colors">
      <span className="text-[9px] font-bold uppercase tracking-wider text-[#8996A6]">{label}</span>
      {open ? <ChevronUp size={11} className="text-[#3A4A5C]" /> : <ChevronDown size={11} className="text-[#3A4A5C]" />}
    </button>
    {open && <div className="px-3 pb-3">{children}</div>}
  </div>
);
const OList: React.FC<{ label: string; items: string[]; color: string }> = ({ label, items, color }) => {
  if (!items.length) return null;
  return (
    <div className="mt-2">
      <span className="text-[8px] uppercase text-[#3A4A5C] font-bold block mb-1">{label} ({items.length})</span>
      <div className="space-y-1">
        {items.slice(0, 5).map((v, i) => (
          <div key={i} className="font-mono text-[10px] px-2 py-1 rounded bg-[#080C12] border border-[#131A22] truncate" style={{ color }}>{v}</div>
        ))}
        {items.length > 5 && <span className="text-[8px] text-[#3A4A5C]">+{items.length - 5} more</span>}
      </div>
    </div>
  );
};
const AttrBound: React.FC<{ text?: string }> = ({ text }) => (
  <div className="p-3 rounded bg-[#0D0810] border border-[#FF453A]/20 text-[9px] text-[#6B7A8D] leading-relaxed">
    <div className="flex items-center gap-1.5 mb-1">
      <AlertTriangle size={9} className="text-[#FF453A] flex-shrink-0" />
      <span className="text-[#FF453A] font-bold uppercase text-[8px] tracking-wider">Forensic Attribution Boundary</span>
    </div>
    <p>{text || 'Campaign grouping indicates observed infrastructure and behavioral correlation. It does not establish common physical actor identity.'}</p>
  </div>
);

// ── Evidence Panel ─────────────────────────────────────────────────────────────
const EvidencePanel: React.FC<{ detail: CampaignDetail | null; selectedNode: GraphNode | null; loading: boolean }> = ({ detail, selectedNode, loading }) => {
  const [openSec, setOpenSec] = useState<string>('summary');
  const tog = (s: string) => setOpenSec(o => o === s ? '' : s);

  if (loading && !detail) return (
    <div className="flex-1 flex items-center justify-center p-6">
      <div className="text-center text-xs text-[#4B5968] space-y-2"><RefreshCw size={14} className="mx-auto animate-spin text-[#5B8DEF]" /><p>Loading...</p></div>
    </div>
  );
  if (!detail) return (
    <div className="flex-1 flex items-center justify-center p-6">
      <div className="text-center text-xs text-[#3A4A5C] space-y-2"><Info size={16} className="mx-auto text-[#1D2633]" /><p>Select a campaign to view evidence.</p></div>
    </div>
  );

  const { campaign, cases, observables_summary, disclaimer } = detail;

  if (selectedNode) {
    const c = cases.find((x: any) => selectedNode.id.includes(x.case_number));
    return (
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        <div className="p-3 rounded-lg bg-[#0C1420] border border-[#1D2633]">
          <div className="flex items-center gap-2 mb-2">
            <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS[selectedNode.type] || '#8996A6' }} />
            <span className="font-mono text-[9px] text-[#4B5968] uppercase">{selectedNode.type}</span>
          </div>
          <p className="font-semibold text-[#E8EDF3] break-all text-[11px] leading-relaxed">{selectedNode.label}</p>
        </div>
        {selectedNode.type === 'CAMPAIGN' && (
          <div className="space-y-2">
            <SLabel>Campaign Metadata</SLabel>
            <FRow label="Confidence" value={campaign.confidence || '--'} />
            <FRow label="Status" value={campaign.status || '--'} />
            <FRow label="Related Cases" value={String(detail.case_count)} />
            <FRow label="First Observed" value={fmtDate(campaign.first_observed_at)} />
            <FRow label="Last Observed" value={fmtDate(campaign.last_observed_at)} />
            {campaign.explanation && <div className="mt-2 p-3 rounded bg-[#080C12] border border-[#5B8DEF]/15 text-[10px] text-[#8996A6] leading-relaxed">{campaign.explanation}</div>}
          </div>
        )}
        {selectedNode.type === 'CASE' && c && (
          <div className="space-y-2">
            <SLabel>Case Record</SLabel>
            <FRow label="Case #" value={c.case_number} />
            <FRow label="Risk Score" value={`${c.risk_score}/100`} />
            <FRow label="Threat Type" value={c.threat_type} />
            <FRow label="Status" value={c.status} />
            <FRow label="Registered" value={fmtDT(c.created_at)} />
            <p className="text-[10px] text-[#C8D3DF] mt-1 leading-relaxed">{c.title}</p>
          </div>
        )}
        {['DOMAIN', 'IP', 'URL'].includes(selectedNode.type) && (
          <div className="space-y-2">
            <SLabel>Observable</SLabel>
            <div className="p-2.5 rounded bg-[#080C12] border border-[#1D2633] font-mono text-[10px] text-[#E8EDF3] break-all">{selectedNode.label}</div>
            <FRow label="Type" value={selectedNode.type} />
            <p className="text-[9px] text-[#3A4A5C] mt-1 leading-relaxed">Observed across correlated cases. Shared infrastructure is an evidence signal, not proof of shared actor identity.</p>
          </div>
        )}
        {['SENDER', 'REPLY_TO'].includes(selectedNode.type) && (
          <div className="space-y-2">
            <SLabel>{selectedNode.type === 'REPLY_TO' ? 'Reply-To Address' : 'Sender Address'}</SLabel>
            <div className="p-2.5 rounded bg-[#080C12] border border-[#1D2633] font-mono text-[10px] text-[#E8EDF3] break-all">{selectedNode.label}</div>
            <p className="text-[9px] text-[#3A4A5C] mt-1 leading-relaxed">Address observed in emails within this campaign cluster.</p>
          </div>
        )}
        {selectedNode.type === 'EMAIL' && (
          <div className="space-y-2">
            <SLabel>Email Message</SLabel>
            <div className="p-2.5 rounded bg-[#080C12] border border-[#1D2633] text-[10px] text-[#8996A6]">Subject: <span className="text-[#E8EDF3]">{selectedNode.label}</span></div>
            <p className="text-[9px] text-[#3A4A5C]">Full details in the Investigation Workspace.</p>
          </div>
        )}
        <AttrBound text={disclaimer} />
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-4 space-y-3 text-xs">
      <ColSec label="Campaign Summary" open={openSec === 'summary'} onToggle={() => tog('summary')}>
        <div className="grid grid-cols-2 gap-2 mt-2">
          <SCell label="Cases" value={String(detail.case_count)} />
          <SCell label="Confidence" value={campaign.confidence || '--'} />
          <SCell label="Status" value={campaign.status || '--'} />
          <SCell label="Correlation" value={`${campaign.confidence_score ?? '?'}/100`} />
        </div>
        <div className="mt-2 space-y-1">
          <FRow label="First Observed" value={fmtDate(campaign.first_observed_at)} />
          <FRow label="Last Observed" value={fmtDate(campaign.last_observed_at)} />
        </div>
        {campaign.explanation && (
          <div className="mt-3 p-3 rounded bg-[#080C12] border border-[#5B8DEF]/15 text-[9px] text-[#8996A6] leading-relaxed">
            <span className="text-[8px] uppercase font-bold text-[#5B8DEF] block mb-1">Correlation Basis</span>
            {campaign.explanation}
          </div>
        )}
      </ColSec>
      <ColSec label={`Linked Investigations (${cases.length})`} open={openSec === 'cases'} onToggle={() => tog('cases')}>
        {cases.length === 0
          ? <p className="text-[9px] text-[#3A4A5C] mt-2">No linked cases.</p>
          : <div className="mt-2 space-y-2">{cases.map((c: any) => (
              <div key={c.id || c.case_number} className="p-3 rounded bg-[#080C12] border border-[#1D2633]">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-[#5B8DEF] text-[10px]">{c.case_number}</span>
                  <span className="font-mono font-bold text-[#F2B84B] text-[10px]">{c.risk_score}/100</span>
                </div>
                <p className="text-[10px] text-[#8996A6] mt-1 line-clamp-2">{c.title}</p>
                <div className="flex gap-2 mt-1 text-[9px] text-[#3A4A5C] font-mono"><span>{c.threat_type}</span><span>·</span><span>{c.status}</span></div>
              </div>
            ))}</div>
        }
      </ColSec>
      <ColSec label="Observed Infrastructure" open={openSec === 'infra'} onToggle={() => tog('infra')}>
        <OList label="Domains" items={observables_summary?.domains || []} color="#F2B84B" />
        <OList label="IP Addresses" items={observables_summary?.ips || []} color="#EF6262" />
        <OList label="Sender Addresses" items={observables_summary?.senders || []} color="#8996A6" />
        <OList label="Reply-To Addresses" items={observables_summary?.reply_tos || []} color="#EF8262" />
        <OList label="URLs" items={(observables_summary?.urls || []).slice(0, 5)} color="#E8A04B" />
        {!observables_summary?.domains?.length && !observables_summary?.ips?.length
          && <p className="text-[9px] text-[#3A4A5C] mt-2">No infrastructure data extracted yet.</p>}
      </ColSec>
      <AttrBound text={disclaimer} />
    </div>
  );
};

// ── Main Page ──────────────────────────────────────────────────────────────────
export const CampaignInvestigationPage: React.FC = () => {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CampaignDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [graphData, setGraphData] = useState<GraphData>(EMPTY_G);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  useEffect(() => {
    setLoadingList(true);
    const qs = statusFilter !== 'ALL' ? `?status=${statusFilter}` : '';
    fetch(`${API_BASE_URL}/campaigns${qs}`)
      .then(r => r.json())
      .then(data => {
        const items: Campaign[] = (data.items || []).map((c: any) => ({
          ...c, id: c.id || c.campaign_id, confidence_score: c.confidence_score ?? 0, case_count: c.case_count ?? 0,
        }));
        setCampaigns(items);
        if (items.length && !selectedId) setSelectedId(items[0].campaign_id || items[0].id);
      })
      .catch(() => setCampaigns([]))
      .finally(() => setLoadingList(false));
  }, [statusFilter]);

  useEffect(() => {
    if (!selectedId) { setDetail(null); setGraphData(EMPTY_G); return; }
    setSelectedNode(null);
    setLoadingDetail(true);
    fetch(`${API_BASE_URL}/campaigns/${selectedId}`)
      .then(r => r.json()).then(d => setDetail(d)).catch(() => setDetail(null)).finally(() => setLoadingDetail(false));
    setLoadingGraph(true);
    fetch(`${API_BASE_URL}/campaigns/${selectedId}/relationships`)
      .then(r => r.json())
      .then(d => setGraphData({ nodes: d.nodes || [], edges: d.edges || [], summary: d.summary || EMPTY_G.summary }))
      .catch(() => setGraphData(EMPTY_G))
      .finally(() => setLoadingGraph(false));
  }, [selectedId]);

  const filtered = campaigns.filter(c => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return c.name?.toLowerCase().includes(q) || c.campaign_id?.toLowerCase().includes(q) || (c.description || '').toLowerCase().includes(q);
  });

  return (
    <div className="flex flex-col bg-[#080C12] font-sans" style={{ height: 'calc(100vh - 56px)' }}>
      {/* Header */}
      <div className="flex-shrink-0 px-6 py-3.5 border-b border-[#131A22] bg-[#0A1018] flex items-center justify-between">
        <div>
          <h1 className="text-[13px] font-bold text-[#E8EDF3] flex items-center gap-2">
            <Layers size={15} className="text-[#5B8DEF]" />Campaign Intelligence
          </h1>
          <p className="text-[10px] text-[#3A4A5C] mt-0.5 font-mono">
            Deterministic infrastructure correlation {'\u00b7'} {campaigns.length} cluster{campaigns.length !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          {(['ALL', 'ACTIVE', 'REVIEW', 'CLOSED'] as const).map(s => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded text-[9px] font-mono font-bold transition-colors ${statusFilter === s ? 'bg-[#5B8DEF] text-white' : 'bg-[#0F151D] text-[#8996A6] border border-[#25313E] hover:text-[#E8EDF3]'}`}>
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* LEFT */}
        <div className="w-60 flex-shrink-0 flex flex-col border-r border-[#131A22] bg-[#0A1018]">
          <div className="px-3 py-2 border-b border-[#131A22]">
            <input type="text" placeholder="Search campaigns..." value={search} onChange={e => setSearch(e.target.value)}
              className="w-full bg-[#0F151D] border border-[#1D2633] rounded px-2.5 py-1.5 text-[10px] text-[#E8EDF3] placeholder-[#3A4A5C] focus:outline-none focus:border-[#5B8DEF]/40 transition-colors" />
          </div>
          <div className="overflow-y-auto" style={{ maxHeight: selectedId ? '44%' : '100%' }}>
            {loadingList
              ? <div className="py-6 flex justify-center"><RefreshCw size={14} className="animate-spin text-[#5B8DEF]" /></div>
              : filtered.length === 0
                ? <div className="py-8 px-4 text-center text-[10px] text-[#3A4A5C]">
                    <Layers size={16} className="mx-auto mb-2 text-[#1D2633]" />
                    {campaigns.length === 0 ? 'No campaigns yet.\nAnalyse emails to discover correlations.' : 'No matches.'}
                  </div>
                : filtered.map(c => (
                    <CampaignListItem key={c.id || c.campaign_id} campaign={c}
                      isSelected={c.campaign_id === selectedId || c.id === selectedId}
                      onClick={() => setSelectedId(c.campaign_id || c.id)} />
                  ))
            }
          </div>
          {selectedId && (
            <>
              <div className="px-4 py-2 border-t border-b border-[#131A22] bg-[#0C1420] flex items-center gap-1.5 flex-shrink-0">
                <Clock size={9} className="text-[#3A4A5C]" />
                <span className="text-[8px] font-bold uppercase tracking-wider text-[#3A4A5C]">Evidence Timeline</span>
              </div>
              <TimelinePanel events={detail?.timeline || []} loading={loadingDetail && !detail} />
            </>
          )}
        </div>

        {/* CENTER */}
        <div className="flex-1 min-w-0 flex flex-col border-r border-[#131A22] bg-[#080C12]">
          <div className="flex-shrink-0 px-4 py-2.5 border-b border-[#131A22] bg-[#0A1018] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Network size={12} className="text-[#5B8DEF]" />
              <span className="text-[9px] font-bold uppercase tracking-wider text-[#8996A6]">Infrastructure Relationship Graph</span>
              {graphData.summary.total_nodes > 0 && (
                <span className="text-[9px] font-mono text-[#3A4A5C]">{graphData.summary.total_nodes}N {'\u00b7'} {graphData.summary.total_edges}E</span>
              )}
            </div>
            {selectedNode && (
              <button onClick={() => setSelectedNode(null)} className="flex items-center gap-1 text-[9px] text-[#8996A6] hover:text-[#E8EDF3] transition-colors">
                <X size={10} /> Clear
              </button>
            )}
          </div>
          {!selectedId
            ? <div className="flex-1 flex items-center justify-center text-xs text-[#3A4A5C]">
                <div className="text-center space-y-2"><Network size={30} className="mx-auto text-[#1D2633]" /><p>Select a campaign to view its relationship graph.</p></div>
              </div>
            : loadingGraph
              ? <div className="flex-1 flex items-center justify-center"><RefreshCw size={18} className="animate-spin text-[#5B8DEF]" /></div>
              : <CampaignGraph data={graphData} selectedNodeId={selectedNode?.id || null} onSelectNode={setSelectedNode} />
          }
          {graphData.nodes.length > 0 && (
            <div className="flex-shrink-0 px-4 py-2 border-t border-[#131A22] bg-[#0A1018] flex flex-wrap gap-3 items-center">
              {Object.entries(NODE_COLORS).filter(([t]) => graphData.nodes.some(n => n.type === t)).map(([t, c]) => (
                <div key={t} className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: c }} />
                  <span className="text-[8px] font-mono text-[#3A4A5C]">{t}</span>
                </div>
              ))}
              <span className="text-[8px] text-[#1D2633] font-mono ml-auto">Click node {'\u00b7'} Scroll zoom {'\u00b7'} Drag pan</span>
            </div>
          )}
        </div>

        {/* RIGHT */}
        <div className="flex-shrink-0 flex flex-col bg-[#0A1018]" style={{ width: '17rem' }}>
          <div className="flex-shrink-0 px-4 py-2.5 border-b border-[#131A22] flex items-center gap-2">
            {selectedNode
              ? <><span className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS[selectedNode.type] || '#8996A6' }} /><span className="text-[9px] font-bold uppercase tracking-wider text-[#8996A6]">{selectedNode.type} Detail</span></>
              : <><Info size={10} className="text-[#3A4A5C]" /><span className="text-[9px] font-bold uppercase tracking-wider text-[#8996A6]">Evidence Summary</span></>
            }
          </div>
          <EvidencePanel detail={detail} selectedNode={selectedNode} loading={loadingDetail && !detail} />
        </div>
      </div>
    </div>
  );
};
