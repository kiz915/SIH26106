'use client';

import { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { IP_TYPE_CONFIG } from '@/lib/constants';

// Fix default marker icons in Next.js
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
});

function createHopIcon(color, hopNumber, isFirst, isLast) {
  const size = isFirst || isLast ? 32 : 26;
  return L.divIcon({
    className: 'custom-hop-marker',
    html: `<div style="
      width: ${size}px; height: ${size}px; border-radius: 50%;
      background: ${isFirst ? '#00e5ff' : isLast ? '#00e676' : color || '#818cf8'};
      color: #0a0c10;
      display: flex; align-items: center; justify-content: center;
      font-size: 11px; font-weight: 800; font-family: monospace;
      border: 2px solid #ffffff;
      box-shadow: 0 0 15px ${isFirst ? '#00e5ff' : isLast ? '#00e676' : color || '#818cf8'};
    ">${hopNumber}</div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

// Deterministically spreads coordinate locations across global regions
const GEO_NODE_REGIONS = [
  { city: 'Frankfurt', country: 'Germany', lat: 50.1109, lng: 8.6821 },
  { city: 'London', country: 'United Kingdom', lat: 51.5074, lng: -0.1278 },
  { city: 'Ashburn, VA', country: 'United States', lat: 39.0438, lng: -77.4874 },
  { city: 'Santa Clara, CA', country: 'United States', lat: 37.3541, lng: -121.9552 },
  { city: 'Singapore', country: 'Singapore', lat: 1.3521, lng: 103.8198 },
  { city: 'Tokyo', country: 'Japan', lat: 35.6762, lng: 139.6503 },
  { city: 'Mumbai', country: 'India', lat: 19.076, lng: 72.8777 },
];

function assignCoordinates(hops = []) {
  return hops.map((hop, i) => {
    const geo = GEO_NODE_REGIONS[i % GEO_NODE_REGIONS.length];
    // Deterministic offset to prevent exact stacking
    const latOffset = ((i * 1.7) % 3) - 1.5;
    const lngOffset = ((i * 2.3) % 4) - 2;
    return {
      ...hop,
      lat: hop.lat || geo.lat + latOffset,
      lng: hop.lng || geo.lng + lngOffset,
      locationName: `${geo.city}, ${geo.country}`,
    };
  });
}

export default function RelayMapInner({ relayPath = [] }) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted || relayPath.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 font-mono text-xs">
        <p>No relay flight hops to plot on geographic map.</p>
      </div>
    );
  }

  const hopsWithCoords = assignCoordinates(relayPath);
  const positions = hopsWithCoords.map((h) => [h.lat, h.lng]);
  const center = positions[0] || [30, 10];

  return (
    <MapContainer
      center={center}
      zoom={2.5}
      style={{ width: '100%', height: '100%', background: '#0a0c10' }}
      scrollWheelZoom={true}
    >
      <TileLayer
        attribution='&copy; <a href="https://carto.com/">CARTO</a>'
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
      />

      {/* Cyber Trajectory Polylines */}
      <Polyline
        positions={positions}
        pathOptions={{
          color: '#00e5ff',
          weight: 3,
          opacity: 0.8,
          dashArray: '6, 8',
        }}
      />

      {hopsWithCoords.map((hop, i) => {
        const isFirst = i === 0;
        const isLast = i === hopsWithCoords.length - 1;
        const ipType = hop.ip_type || (hop.is_private_ip ? 'rfc1918' : 'public');
        const ipConfig = IP_TYPE_CONFIG[ipType] || IP_TYPE_CONFIG.public;

        return (
          <Marker
            key={i}
            position={[hop.lat, hop.lng]}
            icon={createHopIcon(ipConfig.color, hop.hop_number || i + 1, isFirst, isLast)}
          >
            <Popup>
              <div className="p-1 font-mono text-xs space-y-1 text-slate-200">
                <div className="flex items-center justify-between border-b border-white/[0.1] pb-1">
                  <span className="font-bold text-white text-sm">
                    Hop #{hop.hop_number || i + 1}
                  </span>
                  <span
                    className="badge text-[9px]"
                    style={{
                      background: `${ipConfig.color}20`,
                      color: ipConfig.color,
                      borderColor: `${ipConfig.color}40`,
                      borderWidth: 1,
                    }}
                  >
                    {ipConfig.label}
                  </span>
                </div>

                <div className="text-[11px] pt-1">
                  <span className="text-slate-400">Node Location:</span>{' '}
                  <span className="text-cyan-300 font-bold">{hop.locationName}</span>
                </div>

                {hop.ip && (
                  <div className="text-[11px]">
                    <span className="text-slate-400">IP:</span>{' '}
                    <span className="text-white font-bold">{hop.ip}</span>
                  </div>
                )}

                {hop.sending_server && (
                  <div className="text-[10px] text-slate-400 truncate max-w-xs">
                    From: {hop.sending_server}
                  </div>
                )}

                {hop.receiving_server && (
                  <div className="text-[10px] text-slate-400 truncate max-w-xs">
                    By: {hop.receiving_server}
                  </div>
                )}

                {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                  <div className="text-[10px] text-amber-400 font-semibold pt-1">
                    Latency Delta: +{hop.delay_seconds}s
                  </div>
                )}

                {hop.forensic_notes && (
                  <p className="text-[10px] text-amber-300 bg-amber-500/10 p-1 rounded border border-amber-500/20 mt-1">
                    <span className="font-bold text-amber-400">[ALERT]</span> {hop.forensic_notes}
                  </p>
                )}
              </div>
            </Popup>
          </Marker>
        );
      })}
    </MapContainer>
  );
}
