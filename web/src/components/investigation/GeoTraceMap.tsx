import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Globe, MapPin, Layers, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';

export interface GeoHop {
  hopNumber: number;
  ip: string;
  country?: string;
  city?: string;
  region?: string;
  isp?: string;
  asn?: string;
  lat?: number;
  lon?: number;
  isOrigin?: boolean;
  isTor?: boolean;
  isPrivate?: boolean;
}

interface GeoTraceMapProps {
  hops: GeoHop[];
  className?: string;
}

// Curved arc between two LatLngs (great-circle approximation using polyline with parabolic lift)
function buildArcPoints(from: [number, number], to: [number, number], steps = 60): L.LatLngExpression[] {
  const points: L.LatLngExpression[] = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const lat = from[0] + (to[0] - from[0]) * t;
    // Longitude interpolation with dateline wrap handling
    let lngDiff = to[1] - from[1];
    if (lngDiff > 180) lngDiff -= 360;
    if (lngDiff < -180) lngDiff += 360;
    const lng = from[1] + lngDiff * t;
    // Dynamic parabolic arc lift based on global geographic distance
    const dist = Math.hypot(to[0] - from[0], lngDiff);
    const lift = Math.sin(Math.PI * t) * Math.min(Math.max(dist * 0.18, 2.5), 24);
    points.push([lat + lift, lng]);
  }
  return points;
}

const COLORS = {
  origin: '#FF5E5E',
  relay: '#F59E0B',
  destination: '#10B981',
  tor: '#EF4444',
  private: '#64748B',
  arc: '#38BDF8',
};

export const GeoTraceMap: React.FC<GeoTraceMapProps> = ({ hops, className = '' }) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedHop, setSelectedHop] = useState<GeoHop | null>(null);

  const validHops = hops.filter(
    h => h.lat !== undefined && h.lat !== null && h.lon !== undefined && h.lon !== null
  );

  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Destroy previous map
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    const defaultCenter: [number, number] =
      validHops.length > 0 ? [validHops[0].lat!, validHops[0].lon!] : [20, 0];

    const map = L.map(mapContainerRef.current, {
      center: defaultCenter,
      zoom: validHops.length > 0 ? 3 : 2,
      attributionControl: false,
      zoomControl: false,
      scrollWheelZoom: true,
    });

    // Dark tile styling applied directly to map pane
    const pane = map.getPane('tilePane');
    if (pane) {
      pane.style.filter =
        'invert(1) hue-rotate(195deg) saturate(0.35) brightness(0.7)';
    }

    // Free OSM tiles
    const tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
    });
    tileLayer.addTo(map);
    tileLayer.on('add', () => {
      const p = map.getPane('tilePane');
      if (p) {
        p.style.filter =
          'invert(1) hue-rotate(195deg) saturate(0.35) brightness(0.7)';
      }
    });

    const latLngs: [number, number][] = [];

    // Place markers
    validHops.forEach((hop, idx) => {
      const pos: [number, number] = [hop.lat!, hop.lon!];
      latLngs.push(pos);

      const isOrigin = hop.isOrigin ?? idx === 0;
      const isLast = idx === validHops.length - 1 && validHops.length > 1;
      const isTor = Boolean(hop.isTor);

      const color = isTor
        ? COLORS.tor
        : isOrigin
        ? COLORS.origin
        : isLast
        ? COLORS.destination
        : COLORS.relay;

      const label = isOrigin ? 'O' : isLast ? 'M' : String(idx + 1);

      const markerHtml = `
        <div style="position:relative; display:flex; align-items:center; justify-content:center;">
          ${isOrigin ? `<div style="
            position:absolute;
            width:28px; height:28px;
            border-radius:50%;
            background:${color}22;
            border:1.5px solid ${color}55;
            animation: mapPulse 2.5s ease-out infinite;
          "></div>` : ''}
          <div style="
            position:relative;
            width:20px; height:20px;
            border-radius:50%;
            background:linear-gradient(135deg, ${color}, ${color}aa);
            border:2px solid #0B1017;
            box-shadow: 0 0 10px ${color}55, 0 2px 6px rgba(0,0,0,0.5);
            display:flex; align-items:center; justify-content:center;
            font-size:9px; font-weight:800; color:#fff;
            font-family: 'Inter', monospace;
          ">${label}</div>
        </div>
      `;

      const icon = L.divIcon({
        className: 'anvesh-map-node',
        html: markerHtml,
        iconSize: [28, 28],
        iconAnchor: [14, 14],
      });

      const marker = L.marker(pos, { icon }).addTo(map);

      // Popup
      const role = isTor
        ? 'TOR EXIT RELAY'
        : isOrigin
        ? 'ORIGIN MTA'
        : isLast
        ? 'DESTINATION MX'
        : `RELAY HOP ${hop.hopNumber}`;

      const popupHtml = `
        <div style="
          font-family: 'Inter', system-ui, sans-serif;
          background: #0D1625;
          color: #E8EDF3;
          padding: 12px;
          border-radius: 10px;
          border: 1px solid ${color}44;
          min-width: 200px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.6), 0 0 16px ${color}22;
        ">
          <div style="font-size:10px; font-weight:700; color:${color}; margin-bottom:6px; letter-spacing:0.08em;">
            ${role}
          </div>
          <div style="font-size:13px; font-weight:700; font-family:monospace; color:#38BDF8; margin-bottom:6px;">
            ${hop.ip}
          </div>
          ${hop.city || hop.country ? `
          <div style="display:flex; align-items:center; gap:5px; font-size:11px; color:#94A3B8; margin-bottom:4px;">
            <span>📍</span>
            <span>${[hop.city, hop.region, hop.country].filter(Boolean).join(', ')}</span>
          </div>` : ''}
          ${hop.lat !== null && hop.lat !== undefined ? `
          <div style="font-size:10px; color:#475569; margin-bottom:4px;">
            ${hop.lat.toFixed(4)}, ${hop.lon?.toFixed(4)}
          </div>` : ''}
          ${hop.isp ? `
          <div style="font-size:10px; color:#64748B; padding-top:6px; border-top:1px solid #1E293B; margin-top:4px;">
            🏢 ${hop.isp}${hop.asn ? ` <span style="color:#38BDF8">${hop.asn}</span>` : ''}
          </div>` : ''}
        </div>
      `;
      marker.bindPopup(popupHtml, {
        className: 'anvesh-leaflet-popup',
        closeButton: true,
        maxWidth: 260,
      });

      // Click: select hop in sidebar
      marker.on('click', () => setSelectedHop(hop));
    });

    // Draw curved arcs between consecutive hops
    for (let i = 0; i < latLngs.length - 1; i++) {
      const arcPoints = buildArcPoints(latLngs[i], latLngs[i + 1]);

      // Glow underline arc
      L.polyline(arcPoints, {
        color: COLORS.arc,
        weight: 6,
        opacity: 0.08,
      }).addTo(map);

      // Main arc
      L.polyline(arcPoints, {
        color: COLORS.arc,
        weight: 1.5,
        opacity: 0.75,
        dashArray: '5, 7',
        lineCap: 'round',
      }).addTo(map);
    }

    // Fit bounds
    if (latLngs.length > 1) {
      map.fitBounds(L.latLngBounds(latLngs), { padding: [48, 48] });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 5);
    }

    mapInstanceRef.current = map;

    const resizeTimer = setTimeout(() => {
      map.invalidateSize();
    }, 250);

    return () => {
      clearTimeout(resizeTimer);
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [hops]);

  // Resize map when fullscreen toggles
  useEffect(() => {
    setTimeout(() => mapInstanceRef.current?.invalidateSize(), 100);
  }, [isFullscreen]);

  return (
    <div
      className={`relative rounded-xl border border-[#1E293B] bg-[#060A11] shadow-2xl overflow-hidden ${className}`}
      style={isFullscreen ? { position: 'fixed', inset: 0, zIndex: 9999, borderRadius: 0 } : {}}
    >
      {/* Keyframe for pulse animation injected once */}
      <style>{`
        @keyframes mapPulse {
          0% { transform: scale(1); opacity: 0.7; }
          70% { transform: scale(2.2); opacity: 0; }
          100% { transform: scale(1); opacity: 0; }
        }
        .anvesh-leaflet-popup .leaflet-popup-content-wrapper {
          background: transparent !important;
          border: none !important;
          box-shadow: none !important;
          padding: 0 !important;
        }
        .anvesh-leaflet-popup .leaflet-popup-tip-container { display: none; }
        .anvesh-map-node { background: transparent !important; border: none !important; }
      `}</style>

      {/* Top Header Bar */}
      <div className="absolute top-0 left-0 right-0 z-[500] flex items-center justify-between px-3 py-2 bg-gradient-to-b from-[#060A11]/95 to-transparent pointer-events-none">
        <div className="flex items-center gap-2 bg-[#0D1828]/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-[#1E293B]/70 pointer-events-auto">
          <Globe size={13} className="text-[#38BDF8]" />
          <span className="text-[11px] font-bold text-[#E2E8F0] tracking-wide">
            SMTP Transit Route Telemetry
          </span>
          <span className="text-[#334155] text-[10px]">|</span>
          <span className="text-[10px] text-[#38BDF8] font-mono">
            {validHops.length} node{validHops.length !== 1 ? 's' : ''} mapped
          </span>
        </div>
        <div className="flex items-center gap-1.5 pointer-events-auto">
          <button
            onClick={() => mapInstanceRef.current?.zoomIn()}
            className="w-7 h-7 rounded-lg bg-[#0D1828]/80 backdrop-blur-md border border-[#1E293B]/70 flex items-center justify-center text-[#94A3B8] hover:text-[#38BDF8] hover:border-[#38BDF8]/40 transition-all"
          >
            <ZoomIn size={13} />
          </button>
          <button
            onClick={() => mapInstanceRef.current?.zoomOut()}
            className="w-7 h-7 rounded-lg bg-[#0D1828]/80 backdrop-blur-md border border-[#1E293B]/70 flex items-center justify-center text-[#94A3B8] hover:text-[#38BDF8] hover:border-[#38BDF8]/40 transition-all"
          >
            <ZoomOut size={13} />
          </button>
          <button
            onClick={() => setIsFullscreen(f => !f)}
            className="w-7 h-7 rounded-lg bg-[#0D1828]/80 backdrop-blur-md border border-[#1E293B]/70 flex items-center justify-center text-[#94A3B8] hover:text-[#38BDF8] hover:border-[#38BDF8]/40 transition-all"
          >
            <Maximize2 size={13} />
          </button>
        </div>
      </div>

      {/* Map */}
      <div
        ref={mapContainerRef}
        className="w-full z-[1]"
        style={{ height: isFullscreen ? '100vh' : '320px' }}
      />

      {/* Selected Hop Sidebar */}
      {selectedHop && (
        <div className="absolute top-12 right-2 z-[500] w-52 bg-[#0D1828]/95 backdrop-blur-md border border-[#1E293B] rounded-xl p-3 shadow-2xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[#38BDF8] tracking-wide">SELECTED NODE</span>
            <button onClick={() => setSelectedHop(null)} className="text-[#475569] hover:text-[#94A3B8] text-xs">✕</button>
          </div>
          <div className="text-xs font-mono font-bold text-[#E2E8F0] mb-1">{selectedHop.ip}</div>
          {(selectedHop.city || selectedHop.country) && (
            <div className="flex items-center gap-1 text-[10px] text-[#94A3B8] mb-1">
              <MapPin size={9} className="text-[#38BDF8]" />
              {[selectedHop.city, selectedHop.country].filter(Boolean).join(', ')}
            </div>
          )}
          {selectedHop.isp && (
            <div className="text-[10px] text-[#64748B] mb-1 truncate">{selectedHop.isp}</div>
          )}
          {selectedHop.lat !== undefined && selectedHop.lat !== null && (
            <div className="text-[10px] font-mono text-[#38BDF8]/70">
              {selectedHop.lat.toFixed(4)}, {selectedHop.lon?.toFixed(4)}
            </div>
          )}
        </div>
      )}

      {/* Bottom Legend */}
      <div className="absolute bottom-0 left-0 right-0 z-[500] flex items-center gap-3 px-3 py-2 bg-gradient-to-t from-[#060A11]/95 to-transparent pointer-events-none flex-wrap">
        {[
          { color: COLORS.origin, label: 'Origin MTA' },
          { color: COLORS.relay, label: 'Transit Relay' },
          { color: COLORS.destination, label: 'Destination MX' },
          { color: COLORS.tor, label: 'TOR Exit' },
          { color: COLORS.arc, label: 'Route Arc' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
            <span className="text-[10px] text-[#64748B]">{label}</span>
          </div>
        ))}
        <span className="ml-auto text-[9px] text-[#334155]">© OpenStreetMap</span>
      </div>

      {/* Empty state */}
      {validHops.length === 0 && (
        <div className="absolute inset-0 z-[600] flex flex-col items-center justify-center bg-[#060A11]/90 backdrop-blur-sm text-center p-6">
          <div className="w-12 h-12 rounded-2xl border border-[#1E293B] bg-[#0D1525] flex items-center justify-center mb-3">
            <MapPin size={22} className="text-[#334155]" />
          </div>
          <div className="text-sm font-semibold text-[#94A3B8] mb-1">No Resolvable Coordinates</div>
          <p className="text-xs text-[#475569] max-w-xs">
            All relay hops occur over private RFC-1918 subnets or unresolvable internal relays.
          </p>
        </div>
      )}
    </div>
  );
};
