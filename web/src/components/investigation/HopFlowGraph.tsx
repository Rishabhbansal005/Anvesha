import React, { useState } from 'react';
import {
  ArrowRight, Server, ShieldAlert, MapPin, Globe, Wifi,
  Building2, Radio, AlertTriangle, CheckCircle, Lock
} from 'lucide-react';

export interface FlowHop {
  hopNumber: number;
  ip: string;
  country?: string;
  city?: string;
  region?: string;
  isp?: string;
  asn?: string;
  lat?: number;
  lon?: number;
  delaySeconds?: number;
  isOrigin?: boolean;
  isTor?: boolean;
  isPrivate?: boolean;
  authStatus?: 'PASS' | 'FAIL' | 'NEUTRAL';
}

interface HopFlowGraphProps {
  hops: FlowHop[];
  className?: string;
}

function NodeIcon({ isOrigin, isLast, isTor, isPrivate }: { isOrigin: boolean; isLast: boolean; isTor: boolean; isPrivate: boolean }) {
  if (isTor) return <ShieldAlert size={15} className="text-[#EF4444]" />;
  if (isPrivate) return <Lock size={15} className="text-[#64748B]" />;
  if (isOrigin) return <Radio size={15} className="text-[#FF5E5E]" />;
  if (isLast) return <Globe size={15} className="text-[#10B981]" />;
  return <Server size={15} className="text-[#F59E0B]" />;
}

function RiskPill({ isOrigin, isLast, isTor, isPrivate }: { isOrigin: boolean; isLast: boolean; isTor: boolean; isPrivate: boolean }) {
  if (isTor) return <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30"><AlertTriangle size={9} />TOR EXIT</span>;
  if (isPrivate) return <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#475569]/20 text-[#94A3B8] border border-[#475569]/40">RFC-1918</span>;
  if (isOrigin) return <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#FF5E5E]/15 text-[#FF5E5E] border border-[#FF5E5E]/30">ORIGIN MTA</span>;
  if (isLast) return <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/30"><CheckCircle size={9} />MX GATEWAY</span>;
  return <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30">TRANSIT</span>;
}

export const HopFlowGraph: React.FC<HopFlowGraphProps> = ({ hops, className = '' }) => {
  const [selectedHop, setSelectedHop] = useState<number | null>(null);

  if (!hops || hops.length === 0) return null;

  return (
    <div className={`rounded-xl border border-[#1E293B] bg-[#070C14] shadow-2xl overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1E293B] bg-[#0A0F1A]">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-[#38BDF8]/10 border border-[#38BDF8]/20 flex items-center justify-center">
            <Wifi size={14} className="text-[#38BDF8]" />
          </div>
          <div>
            <div className="text-xs font-bold text-[#E2E8F0] tracking-wide">Multi-Hop Transmission Path</div>
            <div className="text-[10px] text-[#475569] mt-0.5">RFC-822 Chronological Order</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-[#38BDF8] font-mono bg-[#38BDF8]/10 px-2 py-1 rounded-md border border-[#38BDF8]/20">
            {hops.length} hop{hops.length !== 1 ? 's' : ''} traced
          </span>
        </div>
      </div>

      {/* Flow Row */}
      <div className="overflow-x-auto p-4">
        <div className="flex items-stretch gap-0 min-w-max">
          {hops.map((hop, idx) => {
            const isOrigin = hop.isOrigin ?? idx === 0;
            const isLast = idx === hops.length - 1 && hops.length > 1;
            const isTor = Boolean(hop.isTor);
            const isPrivate = Boolean(hop.isPrivate);
            const isSelected = selectedHop === idx;

            const borderColor = isTor
              ? '#EF4444'
              : isOrigin
              ? '#FF5E5E'
              : isLast
              ? '#10B981'
              : isPrivate
              ? '#475569'
              : '#F59E0B';

            const bgGlow = isTor
              ? 'rgba(239,68,68,0.06)'
              : isOrigin
              ? 'rgba(255,94,94,0.06)'
              : isLast
              ? 'rgba(16,185,129,0.06)'
              : 'rgba(15,23,42,0.8)';

            return (
              <React.Fragment key={idx}>
                {/* Node Card */}
                <div
                  onClick={() => setSelectedHop(isSelected ? null : idx)}
                  className="flex-shrink-0 w-52 cursor-pointer select-none rounded-xl border transition-all duration-200"
                  style={{
                    borderColor: isSelected ? borderColor : `${borderColor}44`,
                    background: bgGlow,
                    boxShadow: isSelected ? `0 0 18px ${borderColor}22, inset 0 0 12px ${borderColor}08` : 'none',
                  }}
                >
                  {/* Top accent line */}
                  <div className="h-[3px] w-full rounded-t-xl" style={{ background: `linear-gradient(90deg, ${borderColor}, ${borderColor}55)` }} />

                  <div className="p-3">
                    {/* Badge row */}
                    <div className="flex items-center justify-between mb-2">
                      <RiskPill isOrigin={isOrigin} isLast={isLast} isTor={isTor} isPrivate={isPrivate} />
                      <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: `${borderColor}18`, border: `1px solid ${borderColor}30` }}>
                        <NodeIcon isOrigin={isOrigin} isLast={isLast} isTor={isTor} isPrivate={isPrivate} />
                      </div>
                    </div>

                    {/* Hop number + IP */}
                    <div className="text-[10px] text-[#475569] font-mono mb-0.5">
                      HOP {hop.hopNumber}
                    </div>
                    <div className="text-sm font-mono font-bold text-[#E8EDF3] tracking-tight truncate" title={hop.ip}>
                      {hop.ip || '—'}
                    </div>

                    {/* Location */}
                    {(hop.city || hop.country) && (
                      <div className="flex items-center gap-1 mt-2 text-[11px] text-[#94A3B8]">
                        <MapPin size={10} className="flex-shrink-0" style={{ color: borderColor }} />
                        <span className="truncate">{[hop.city, hop.country].filter(Boolean).join(', ')}</span>
                      </div>
                    )}

                    {/* ISP */}
                    {hop.isp && (
                      <div className="flex items-center gap-1 mt-1 text-[10px] text-[#64748B]">
                        <Building2 size={9} className="flex-shrink-0" />
                        <span className="truncate">{hop.isp}</span>
                      </div>
                    )}

                    {/* Expanded detail */}
                    {isSelected && (
                      <div className="mt-2 pt-2 border-t border-[#1E293B]/80 space-y-1">
                        {hop.asn && (
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-[#475569]">ASN</span>
                            <span className="font-mono text-[#E2E8F0]">{hop.asn}</span>
                          </div>
                        )}
                        {hop.lat !== undefined && hop.lat !== null && (
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-[#475569]">Coordinates</span>
                            <span className="font-mono text-[#38BDF8]">{hop.lat.toFixed(3)}, {hop.lon?.toFixed(3)}</span>
                          </div>
                        )}
                        {hop.region && (
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-[#475569]">Region</span>
                            <span className="text-[#94A3B8]">{hop.region}</span>
                          </div>
                        )}
                        {hop.delaySeconds !== undefined && (
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-[#475569]">Delay</span>
                            <span className="text-[#F59E0B]">{hop.delaySeconds}s</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* Connector */}
                {!isLast && (
                  <div className="flex flex-col items-center justify-center px-1 flex-shrink-0 relative">
                    {hops[idx + 1]?.delaySeconds !== undefined && hops[idx + 1]?.delaySeconds! > 0 ? (
                      <span className="text-[9px] font-mono text-[#F59E0B] font-bold mb-1 bg-[#0D1625] px-1.5 py-0.5 rounded border border-[#F59E0B]/30 shadow-sm">
                        +{hops[idx + 1].delaySeconds}s
                      </span>
                    ) : (
                      <span className="text-[8px] font-mono text-[#475569] mb-1">relay</span>
                    )}
                    <div className="flex items-center relative">
                      {/* Animated line */}
                      <div className="relative flex items-center w-12">
                        <div
                          className="absolute left-0 right-0 h-[1.5px]"
                          style={{
                            background: 'linear-gradient(90deg, #38BDF844, #38BDF8, #38BDF844)',
                            boxShadow: '0 0 6px #38BDF866',
                          }}
                        />
                        {/* Flow dots */}
                        <div className="absolute left-1/3 w-1.5 h-1.5 rounded-full bg-[#38BDF8] animate-ping" style={{ animationDelay: `${idx * 200}ms`, animationDuration: '2s' }} />
                      </div>
                      <ArrowRight size={13} className="text-[#38BDF8] flex-shrink-0 ml-[-3px]" />
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Footer legend */}
      <div className="px-4 py-2 border-t border-[#1E293B]/60 bg-[#060A11] flex items-center gap-4 flex-wrap">
        <span className="text-[10px] text-[#475569]">Click a node to expand details</span>
        <div className="flex items-center gap-3 ml-auto flex-wrap">
          {[
            { color: '#FF5E5E', label: 'Origin MTA' },
            { color: '#F59E0B', label: 'Transit Relay' },
            { color: '#10B981', label: 'Destination MX' },
            { color: '#EF4444', label: 'TOR Exit' },
            { color: '#64748B', label: 'Private Net' },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: color }} />
              <span className="text-[10px] text-[#64748B]">{label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
