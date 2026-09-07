'use client';

import { useState } from 'react';
import { Route, Clock, Server, ArrowDown, AlertTriangle, ShieldCheck, MapPin } from 'lucide-react';
import Link from 'next/link';
import { IP_TYPE_CONFIG } from '@/lib/constants';

export default function RelayTimeline({ relayPath = [], caseId }) {
  const [expandedHop, setExpandedHop] = useState(null);

  if (!relayPath || relayPath.length === 0) {
    return (
      <div className="glass-card p-5">
        <div className="flex items-center gap-2 mb-3">
          <Route className="w-5 h-5 text-[var(--primary-cyan)]" />
          <h3 className="text-sm font-bold text-[var(--text-primary)]">
            Relay Transit Path
          </h3>
        </div>
        <p className="text-center py-6 text-xs text-[var(--text-muted)]">
          No intermediate transit hops found in Received headers.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-card p-5 h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Route className="w-5 h-5 text-[var(--primary-cyan)]" />
            <h3 className="text-sm font-bold text-[var(--text-primary)]">
              Relay Transit Path ({relayPath.length} Hops)
            </h3>
          </div>
          {caseId && (
            <Link
              href={`/map/${encodeURIComponent(caseId)}`}
              className="inline-flex items-center gap-1 text-xs font-bold text-[var(--primary-cyan)] hover:underline transition-colors"
            >
              <MapPin className="w-3.5 h-3.5" />
              <span>Full Map</span>
            </Link>
          )}
        </div>

        <p className="text-xs text-[var(--text-secondary)] mb-4">
          Hop 1 is closest to origin sender; last hop delivered into destination mailbox.
        </p>

        {/* Timeline Stack */}
        <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-[2px] before:bg-gradient-to-b before:from-[var(--primary-cyan)] before:via-indigo-500 before:to-[var(--border-subtle)]">
          {relayPath.map((hop, index) => {
            const isFirst = index === 0;
            const isLast = index === relayPath.length - 1;
            const ipType = hop.ip_type || (hop.is_private_ip ? 'rfc1918' : 'public');
            const typeConfig = IP_TYPE_CONFIG[ipType] || IP_TYPE_CONFIG.public;

            return (
              <div key={index} className="relative group">
                {/* Node Dot */}
                <div
                  className={`absolute -left-[19px] top-1.5 w-3.5 h-3.5 rounded-full border-2 border-[var(--surface-base)] shadow-[0_0_10px_currentColor] transition-transform group-hover:scale-125 ${
                    isFirst
                      ? 'bg-[var(--primary-cyan)] text-[var(--primary-cyan)]'
                      : isLast
                      ? 'bg-emerald-500 text-emerald-500'
                      : 'bg-indigo-500 text-indigo-500'
                  }`}
                />

                <div className="p-3 rounded-xl bg-[var(--surface-container-low)] border border-[var(--border-subtle)] hover:border-[var(--border-cyan)] transition-all font-mono text-xs space-y-1.5">
                  <div className="flex items-center justify-between flex-wrap gap-1">
                    <span className="font-bold text-[var(--text-primary)] flex items-center gap-1.5">
                      <span className="text-[var(--primary-cyan)]">Hop #{hop.hop_number || index + 1}</span>
                      {isFirst && <span className="text-[10px] text-[var(--primary-cyan)] bg-[var(--primary-cyan)]/15 px-1.5 py-0.2 rounded font-bold">ORIGIN</span>}
                      {isLast && <span className="text-[10px] text-emerald-600 dark:text-emerald-400 bg-emerald-500/15 px-1.5 py-0.2 rounded font-bold">TARGET</span>}
                    </span>

                    {hop.ip && (
                      <span
                        className="badge text-[10px] font-bold"
                        style={{
                          background: `${typeConfig.color}20`,
                          color: typeConfig.color,
                          borderColor: `${typeConfig.color}40`,
                          borderWidth: 1,
                        }}
                      >
                        {typeConfig.label}
                      </span>
                    )}
                  </div>

                  <div className="text-[11px] text-[var(--text-secondary)] space-y-0.5">
                    {hop.sending_server && (
                      <div>
                        <span className="text-[var(--text-muted)]">From:</span> {hop.sending_server}
                      </div>
                    )}
                    {hop.receiving_server && (
                      <div>
                        <span className="text-[var(--text-muted)]">By:</span> {hop.receiving_server}
                      </div>
                    )}
                    {hop.ip && (
                      <div className="text-[var(--primary-cyan)] font-bold">
                        <span className="text-[var(--text-muted)]">IP:</span> {hop.ip}
                      </div>
                    )}
                    {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                      <div className="text-amber-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" /> Hop Delay: {hop.delay_seconds}s
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
