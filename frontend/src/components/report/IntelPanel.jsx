'use client';

import { useState } from 'react';
import { Globe, Server, ShieldAlert, CheckCircle2, AlertTriangle, Cloud, Lock, ExternalLink } from 'lucide-react';

export default function IntelPanel({ ipIntelligence = [], domainIntelligence = [] }) {
  const [activeTab, setActiveTab] = useState('ip');

  return (
    <div className="glass-card p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-[var(--primary-cyan)]" />
          <h3 className="text-sm font-bold text-[var(--text-primary)]">
            Threat Intelligence
          </h3>
        </div>
        <div className="flex gap-1 p-1 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)]">
          <button
            onClick={() => setActiveTab('ip')}
            className={`px-3 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'ip'
                ? 'bg-[var(--surface-base)] text-[var(--primary-cyan)] font-bold border border-[var(--border-cyan)] shadow-sm'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            IP Intel ({ipIntelligence.length})
          </button>
          <button
            onClick={() => setActiveTab('domain')}
            className={`px-3 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'domain'
                ? 'bg-[var(--surface-base)] text-[var(--primary-cyan)] font-bold border border-[var(--border-cyan)] shadow-sm'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            Domain Intel ({domainIntelligence.length})
          </button>
        </div>
      </div>

      {activeTab === 'ip' ? (
        <div className="space-y-3">
          {ipIntelligence.length === 0 ? (
            <p className="text-center py-6 text-xs text-[var(--text-muted)]">
              No public IP intelligence records returned for this case.
            </p>
          ) : (
            ipIntelligence.map((intel, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-[var(--surface-container-low)] border border-[var(--border-subtle)] hover:border-[var(--border-cyan)] transition-all font-mono text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-[var(--primary-cyan)]" />
                    <span className="font-bold text-[var(--text-primary)] text-sm">{intel.ip}</span>
                  </div>
                  <span className="badge text-[10px] bg-[var(--primary-cyan)]/10 text-[var(--primary-cyan)] border border-[var(--border-cyan)] font-bold">
                    {intel.provider || 'Threat Intel Engine'}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px]">
                  <div>
                    <span className="text-[var(--text-muted)] block">Location</span>
                    <span className="text-[var(--text-primary)] font-medium">
                      {[intel.city, intel.region, intel.country].filter(Boolean).join(', ') || 'Unknown'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] block">ASN</span>
                    <span className="text-[var(--text-primary)] font-medium">{intel.asn || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] block">ISP / Org</span>
                    <span className="text-[var(--text-primary)] font-medium truncate block">{intel.isp || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] block">Hosting / VPN</span>
                    <span className={intel.is_vpn_tor ? 'text-rose-500 font-bold' : intel.is_hosting ? 'text-amber-500 font-bold' : 'text-emerald-500 font-bold'}>
                      {intel.is_vpn_tor ? 'VPN/Tor Node (Alert)' : intel.is_hosting ? 'Cloud Hosting' : 'Residential/Corp'}
                    </span>
                  </div>
                </div>

                {intel.disclaimer && (
                  <p className="text-[10px] text-[var(--text-muted)] pt-1 border-t border-[var(--border-subtle)]">
                    Notice: {intel.disclaimer}
                  </p>
                )}
              </div>
            ))
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {domainIntelligence.length === 0 ? (
            <p className="text-center py-6 text-xs text-[var(--text-muted)] font-mono">
              No domain intelligence records returned for this case.
            </p>
          ) : (
            domainIntelligence.map((dIntel, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-[var(--surface-container-low)] border border-[var(--border-subtle)] hover:border-[var(--border-cyan)] transition-all font-mono text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-[var(--primary-cyan)]" />
                    <span className="font-bold text-[var(--text-primary)] text-sm">{dIntel.domain}</span>
                  </div>
                  <span className="badge text-[10px] bg-indigo-500/10 text-indigo-500 border border-indigo-500/30 font-bold">
                    WHOIS / DNS
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px]">
                  <div>
                    <span className="text-[var(--text-muted)] block">Registrar</span>
                    <span className="text-[var(--text-primary)] font-medium truncate block">{dIntel.registrar || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] block">Domain Age</span>
                    <span className={dIntel.is_newly_registered ? 'text-rose-500 font-bold' : 'text-[var(--text-primary)]'}>
                      {dIntel.domain_age_days ? `${dIntel.domain_age_days} days` : 'Established'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] block">Lookalike Risk</span>
                    <span className={dIntel.is_typosquatting ? 'text-rose-500 font-bold' : 'text-emerald-500 font-bold'}>
                      {dIntel.is_typosquatting ? 'Typosquat Detected (Alert)' : 'No Impersonation'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] block">DMARC Policy</span>
                    <span className="text-[var(--text-primary)] font-bold">{dIntel.dmarc_policy || 'None'}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
