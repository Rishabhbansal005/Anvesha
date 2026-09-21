import React, { useState } from 'react';
import { 
  Search, 
  Globe2, 
  Network, 
  ShieldCheck, 
  AlertTriangle,
  Server,
  MapPin,
  Building2,
  ShieldAlert,
  Mail,
  FileCode,
  Cpu,
  Layers,
  Activity
} from 'lucide-react';
import { EmptyState } from '../components/common/EmptyState';
import { API_BASE_URL } from '../constants';
import { GeoTraceMap } from '../components/investigation/GeoTraceMap';

// Formatting Helpers
const formatAsn = (asn: any): string => {
  if (!asn || asn === 'UNAVAILABLE' || asn === 'NONE') return 'Unavailable';
  const clean = String(asn).trim().toUpperCase();
  if (clean.startsWith('AS')) {
    return clean;
  }
  return `AS${clean}`;
};

const formatCountry = (codeOrName: string | null | undefined): string => {
  if (!codeOrName || codeOrName === 'External Public Route (Unenriched)') {
    return 'Global Anycast / Unbound';
  }
  const clean = codeOrName.trim().toUpperCase();
  if (clean.length === 2) {
    try {
      const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
      const fullName = regionNames.of(clean);
      if (fullName) return `${fullName} (${clean})`;
    } catch {
      // fallback
    }
  }
  return codeOrName;
};

const formatEnum = (val: string | null | undefined, fallback: string = 'Standard Routable'): string => {
  if (!val || val === 'UNAVAILABLE' || val === 'NONE') return fallback;
  return val
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
};

export const IntelligencePage: React.FC = () => {
  const [query, setQuery] = useState('');
  const [queryType, setQueryType] = useState<'IP' | 'DOMAIN'>('IP');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const endpoint = queryType === 'IP' 
        ? `${API_BASE_URL}/intelligence/ip/${encodeURIComponent(query.trim())}`
        : `${API_BASE_URL}/intelligence/domain/${encodeURIComponent(query.trim())}`;
      
      const res = await fetch(endpoint);
      if (res.ok) {
        const data = await res.json();
        setResult(data);
      } else {
        const err = await res.json().catch(() => ({}));
        setError(err.detail || 'Unable to retrieve intelligence for this observable.');
        setResult(null);
      }
    } catch (err: any) {
      setError('Connection to intelligence service unavailable.');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickTest = (val: string, type: 'IP' | 'DOMAIN') => {
    setQueryType(type);
    setQuery(val);
    setResult(null);
    setError(null);
  };

  const isTorOrProxy = result?.vpn_tor_proxy_indicator && result.vpn_tor_proxy_indicator !== 'NONE';
  const isFlaggedDomain = result?.status === 'FLAGGED' || result?.classification === 'SUSPECTED_HOMOGLYPH_IMPERSONATION';

  return (
    <div className="space-y-6 max-w-5xl mx-auto py-6 px-4">
      {/* Page Header */}
      <div className="border-b border-[#25313E]/60 pb-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-[#E8EDF3] font-mono flex items-center gap-2.5">
              <Cpu size={22} className="text-[#5B8DEF]" />
              INDICATOR INTELLIGENCE & RECONNAISSANCE
            </h2>
            <p className="text-xs text-[#8996A6] mt-1 font-mono">
              Deterministic on-demand forensic inspection for IP addresses, BGP telemetry, and suspicious lookalike domains.
            </p>
          </div>
          <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-[#5B8DEF]/10 border border-[#5B8DEF]/30 text-[#5B8DEF]">
            RFC 7484 & BGP Engine Live
          </span>
        </div>
      </div>

      {/* Selector Tabs */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => { setQueryType('IP'); setResult(null); setError(null); }}
          className={`px-3.5 py-1.5 rounded text-xs font-mono font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
            queryType === 'IP' 
              ? 'bg-[#5B8DEF] text-white shadow-sm' 
              : 'bg-[#080C12] text-[#8996A6] hover:text-[#E8EDF3] border border-[#25313E]'
          }`}
        >
          <Network size={13} />
          <span>IP Address</span>
        </button>
        <button
          type="button"
          onClick={() => { setQueryType('DOMAIN'); setResult(null); setError(null); }}
          className={`px-3.5 py-1.5 rounded text-xs font-mono font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
            queryType === 'DOMAIN' 
              ? 'bg-[#5B8DEF] text-white shadow-sm' 
              : 'bg-[#080C12] text-[#8996A6] hover:text-[#E8EDF3] border border-[#25313E]'
          }`}
        >
          <Globe2 size={13} />
          <span>Domain Name</span>
        </button>
      </div>
          {/* Query Form */}
          <form onSubmit={handleLookup} className="p-5 rounded-xl bg-[#0F151D] border border-[#25313E] space-y-4 shadow-sm">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <span className="text-xs font-mono font-bold tracking-wider uppercase text-[#8996A6]">
                Target {queryType === 'IP' ? 'IP Observable' : 'Domain Observable'}
              </span>


          {/* Quick Preset Badges */}
          <div className="flex items-center flex-wrap gap-2 text-[11px] font-mono text-[#8996A6]">
            <span>Quick test:</span>
            {queryType === 'IP' ? (
              <>
                <button
                  type="button"
                  onClick={() => handleQuickTest('185.220.101.42', 'IP')}
                  className="px-2.5 py-1 rounded bg-[#1D2633] hover:bg-[#25313E] text-[#5B8DEF] cursor-pointer transition-colors"
                >
                  Tor Node (185.220.101.42)
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickTest('8.8.8.8', 'IP')}
                  className="px-2.5 py-1 rounded bg-[#1D2633] hover:bg-[#25313E] text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer transition-colors"
                >
                  Google DNS (8.8.8.8)
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => handleQuickTest('paypa1-security.com', 'DOMAIN')}
                  className="px-2.5 py-1 rounded bg-[#1D2633] hover:bg-[#25313E] text-[#FF453A] cursor-pointer transition-colors"
                >
                  paypa1-security.com
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickTest('google.com', 'DOMAIN')}
                  className="px-2.5 py-1 rounded bg-[#1D2633] hover:bg-[#25313E] text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer transition-colors"
                >
                  google.com
                </button>
              </>
            )}
          </div>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={queryType === 'IP' ? "Enter IP address (e.g. 185.220.101.42 or 8.8.8.8)..." : "Enter domain (e.g. paypa1-security.com or micros0ft-verify.com)..."}
            className="flex-1 rounded-md border border-[#25313E] bg-[#080C12] px-4 py-2.5 text-xs font-mono text-[#E8EDF3] placeholder-[#8996A6] focus:outline-none focus:ring-1 focus:ring-[#5B8DEF]"
          />
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="px-5 py-2.5 rounded-md bg-[#5B8DEF] hover:bg-[#4a7de0] text-white text-xs font-semibold font-mono transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-2"
          >
            <Search size={14} />
            {loading ? 'Analyzing...' : 'Lookup'}
          </button>
        </div>
      </form>

      {error && (
        <div className="p-4 rounded-lg bg-[#FF453A]/10 border border-[#FF453A]/30 text-xs font-mono text-[#FF453A] flex items-center gap-2">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Results or Clean Empty State */}
      {!result && !loading && !error && (
        <EmptyState
          icon={Globe2}
          title="No intelligence query active"
          description="Enter an IP address or domain to analyze network infrastructure, routing, or lookalike homoglyphs."
        />
      )}

      {/* Comprehensive Intelligence Result Card */}
      {result && (
        <div className="rounded-xl bg-[#0F151D] border border-[#25313E] p-6 space-y-5 shadow-lg">
          {/* Header Banner */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-[#25313E]/80 pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] font-mono uppercase text-[#8996A6]">
                  {result.target_type === 'DOMAIN' ? 'Domain Observable Target' : 'IP Indicator Target'}
                </span>
                {result.confidence && (
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-[#5B8DEF]/20 text-[#5B8DEF] border border-[#5B8DEF]/30">
                    {result.confidence} CONFIDENCE
                  </span>
                )}
              </div>
              <h3 className="font-mono text-base font-bold text-[#E8EDF3] flex items-center gap-2">
                {result.target_type === 'DOMAIN' ? <Globe2 size={16} className="text-[#5B8DEF]" /> : <Network size={16} className="text-[#5B8DEF]" />}
                <span>{result.target}</span>
              </h3>
            </div>

            <div className="flex items-center gap-2">
              <span className={`px-3 py-1 rounded text-xs font-mono font-bold uppercase tracking-wide ${
                result.status === 'FLAGGED' || isFlaggedDomain ? 'bg-[#FF453A]/20 text-[#FF453A] border border-[#FF453A]/40' :
                result.status === 'CLASSIFIED' || result.status === 'ENRICHED' ? 'bg-[#30D158]/20 text-[#30D158] border border-[#30D158]/40' :
                'bg-[#151D27] text-[#E8EDF3] border border-[#25313E]'
              }`}>
                {result.status}
              </span>
            </div>
          </div>

          {/* Critical Indicators / Alerts */}
          {isTorOrProxy && (
            <div className="p-3.5 rounded-lg bg-[#FF453A]/10 border border-[#FF453A]/30 flex items-center gap-3">
              <ShieldAlert size={20} className="text-[#FF453A] shrink-0" />
              <div>
                <span className="text-xs font-bold font-mono text-[#FF453A] block">
                  ANONYMIZATION DETECTED: {formatEnum(result.vpn_tor_proxy_indicator)}
                </span>
                <span className="text-[11px] font-mono text-[#E8EDF3]/80">
                  {result.tor_vpn_observation || 'IP matches known public Tor exit nodes or proxy relays.'}
                </span>
              </div>
            </div>
          )}

          {isFlaggedDomain && result.target_impersonated && (
            <div className="p-3.5 rounded-lg bg-[#FF453A]/10 border border-[#FF453A]/30 flex items-center gap-3">
              <AlertTriangle size={20} className="text-[#FF453A] shrink-0" />
              <div>
                <span className="text-xs font-bold font-mono text-[#FF453A] block">
                  HOMOGLYPH SPOOFING TARGET IDENTIFIED
                </span>
                <span className="text-[11px] font-mono text-[#E8EDF3]/80">
                  This domain appears engineered to impersonate <strong className="text-white font-bold">{result.target_impersonated}</strong> using character substitution or typosquatting.
                </span>
              </div>
            </div>
          )}

          {/* Primary Telemetry Row (3 Responsive Cards) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 text-xs font-mono">
            {/* Box 1: Classification */}
            <div className="p-4 rounded-lg bg-[#080C12] border border-[#25313E] space-y-1.5 min-w-0">
              <span className="text-[10px] text-[#8996A6] uppercase tracking-wider block flex items-center gap-1.5">
                <Layers size={12} className="text-[#5B8DEF]" />
                <span>Classification & Network</span>
              </span>
              <span className="text-[#E8EDF3] font-semibold block text-sm break-words">
                {formatEnum(result.classification, 'Public Routable Gateway')}
              </span>
              <span className="text-[10px] text-[#8996A6] block break-words">
                {result.route_type || (result.target_type === 'DOMAIN' ? 'DNS Registered Host' : 'Public Routable Internet Gateway')}
              </span>
            </div>

            {/* Box 2: Geolocation */}
            <div className="p-4 rounded-lg bg-[#080C12] border border-[#25313E] space-y-1.5 min-w-0">
              <span className="text-[10px] text-[#8996A6] uppercase tracking-wider block flex items-center gap-1.5">
                <MapPin size={12} className="text-[#5B8DEF]" />
                <span>Geographic Location</span>
              </span>
              <span className="text-[#E8EDF3] font-semibold block text-sm break-words">
                {formatCountry(result.country)}
              </span>
              <span className="text-[10px] text-[#8996A6] block">
                {result.city ? `${result.city}${result.region ? `, ${result.region}` : ''}` : 'Authoritative BGP Origin'}
              </span>
            </div>

            {/* Box 3: Routing ASN */}
            <div className="p-4 rounded-lg bg-[#080C12] border border-[#25313E] space-y-1.5 min-w-0">
              <span className="text-[10px] text-[#8996A6] uppercase tracking-wider block flex items-center gap-1.5">
                <Building2 size={12} className="text-[#5B8DEF]" />
                <span>Routing ASN & Origin</span>
              </span>
              <span className="text-[#E8EDF3] font-bold block text-sm font-mono text-[#5B8DEF]">
                {formatAsn(result.asn)}
              </span>
              <span className="text-[10px] text-[#8996A6] block break-words">
                {result.organization && result.organization !== 'UNAVAILABLE' 
                  ? result.organization 
                  : (result.isp && result.isp !== 'UNAVAILABLE' ? result.isp : 'Authoritative BGP Network')}
              </span>
            </div>
          </div>

          {/* Interactive World Map for IP Geolocation */}
          {result.target_type === 'IP' && (result.latitude || result.country) && (
            <GeoTraceMap
              hops={[{
                hopNumber: 1,
                ip: result.indicator,
                country: result.country,
                region: result.region,
                city: result.city,
                isp: result.isp,
                asn: result.asn,
                lat: result.latitude,
                lon: result.longitude,
                isOrigin: true,
                isTor: result.vpn_tor_proxy_indicator === 'TOR_EXIT_RELAY'
              }]}
              className="mt-2"
            />
          )}

          {/* Infrastructure & Network Breakdown for IP */}
          {result.target_type === 'IP' && (
            <div className="space-y-3 font-mono text-xs">
              {/* Hosting Provider (Full-width / 2-column friendly so long names never clip) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="p-4 rounded-lg bg-[#080C12] border border-[#25313E] space-y-1 min-w-0">
                  <span className="text-[10px] text-[#8996A6] uppercase tracking-wider block flex items-center gap-1.5">
                    <Server size={12} className="text-[#5B8DEF]" />
                    <span>Hosting & Infrastructure Provider</span>
                  </span>
                  <p className="text-[#E8EDF3] font-semibold text-xs leading-relaxed break-words">
                    {result.hosting_provider && result.hosting_provider !== 'UNAVAILABLE'
                      ? result.hosting_provider
                      : (result.isp && result.isp !== 'UNAVAILABLE' ? result.isp : 'Public Internet Gateway')}
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-[#080C12] border border-[#25313E] space-y-1 min-w-0">
                  <span className="text-[10px] text-[#8996A6] uppercase tracking-wider block flex items-center gap-1.5">
                    <Activity size={12} className="text-[#5B8DEF]" />
                    <span>Cloud & Network Profile</span>
                  </span>
                  <p className="text-[#E8EDF3] font-semibold text-xs leading-relaxed break-words">
                    {formatEnum(result.cloud_classification, 'Independent Transit Network')}
                  </p>
                </div>
              </div>

              {/* Status Chips Row */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/70 space-y-0.5">
                  <span className="text-[10px] text-[#8996A6] block uppercase">Proxy / Tor Status</span>
                  <span className={`font-bold text-xs ${isTorOrProxy ? 'text-[#FF453A]' : 'text-[#30D158]'}`}>
                    {formatEnum(result.vpn_tor_proxy_indicator, 'None Observed')}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/70 space-y-0.5">
                  <span className="text-[10px] text-[#8996A6] block uppercase">Reputation Score</span>
                  <span className="text-[#E8EDF3] font-bold text-xs">
                    {result.reputation_score !== undefined && result.reputation_score !== null 
                      ? `${result.reputation_score}/100 · ${result.reputation_score > 50 ? 'High Risk' : 'Low Risk'}` 
                      : '0/100 · Neutral'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/70 space-y-0.5 col-span-2 sm:col-span-1">
                  <span className="text-[10px] text-[#8996A6] block uppercase">Evidence Nature</span>
                  <span className="text-[#5B8DEF] font-bold text-xs">
                    {formatEnum(result.evidence_nature, 'Enriched BGP Telemetry')}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Secondary Details for Domain */}
          {result.target_type === 'DOMAIN' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3.5 rounded-lg bg-[#080C12] border border-[#25313E] min-w-0">
                  <span className="text-[10px] text-[#8996A6] block mb-1">DETECTED MAIL PROVIDER</span>
                  <span className="text-[#E8EDF3] font-semibold flex items-center gap-1.5 break-words">
                    <Mail size={13} className="text-[#5B8DEF] shrink-0" />
                    <span>{result.detected_mail_provider || 'Authoritative DNS Records'}</span>
                  </span>
                </div>
                <div className="p-3.5 rounded-lg bg-[#080C12] border border-[#25313E] min-w-0">
                  <span className="text-[10px] text-[#8996A6] block mb-1">HOMOGLYPH RISK</span>
                  <span className={`font-bold block ${isFlaggedDomain ? 'text-[#FF453A]' : 'text-[#30D158]'}`}>
                    {isFlaggedDomain ? 'CRITICAL (Impersonation Target)' : 'CLEAN / BENIGN'}
                  </span>
                </div>
                <div className="p-3.5 rounded-lg bg-[#080C12] border border-[#25313E] min-w-0">
                  <span className="text-[10px] text-[#8996A6] block mb-1">REGISTRAR (RDAP)</span>
                  <span className="text-[#E8EDF3] block break-words">
                    {result.rdap?.registrar || 'ICANN Accredited Registrar'}
                  </span>
                </div>
              </div>

              {/* DNS Records preview */}
              {result.dns_records && Object.keys(result.dns_records).length > 0 && (
                <div className="p-4 rounded-lg bg-[#080C12] border border-[#25313E] space-y-2">
                  <div className="flex items-center gap-2 text-[#8996A6] text-[11px] uppercase border-b border-[#25313E]/60 pb-1.5">
                    <FileCode size={13} />
                    <span>Authoritative DNS Telemetry</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                    {Object.entries(result.dns_records).map(([rtype, rvals]: [string, any]) => (
                      <div key={rtype} className="p-2.5 rounded bg-[#0F151D] border border-[#25313E]/50 min-w-0">
                        <span className="font-bold text-[#5B8DEF] block mb-0.5">{rtype} Record</span>
                        <span className="text-[#8996A6] break-all leading-relaxed">
                          {Array.isArray(rvals) ? rvals.map(v => typeof v === 'object' ? JSON.stringify(v) : String(v)).join(', ') : String(rvals)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Attribution Boundary Invariant Disclaimer */}
          {result.disclaimer && (
            <div className="p-3.5 rounded-lg bg-[#080C12] border border-[#25313E]/80 text-[11px] font-mono text-[#8996A6] leading-relaxed flex items-start gap-2.5">
              <ShieldCheck size={16} className="text-[#5B8DEF] shrink-0 mt-0.5" />
              <div>
                <span className="text-[#E8EDF3] font-bold block mb-0.5">
                  Forensic Attribution Boundary Safeguard:
                </span>
                {result.disclaimer}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
