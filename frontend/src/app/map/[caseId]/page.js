'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { ArrowLeft, Route, Clock, Server, Globe, ShieldAlert, FileText, MapPin } from 'lucide-react';
import { getAnalysis } from '@/lib/storage';
import { getCaseDetail } from '@/lib/api';

const RelayMapInner = dynamic(() => import('@/components/map/RelayMapInner'), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-full text-[var(--primary-cyan)] font-mono text-xs">
      <div className="w-8 h-8 border-2 border-[var(--primary-cyan)] border-t-transparent rounded-full animate-spin mr-3" />
      <span>Loading Cyber Infrastructure Map...</span>
    </div>
  ),
});

export default function CaseMapPage() {
  const params = useParams();
  const router = useRouter();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    const rawCaseId = params?.caseId;
    if (!rawCaseId) return;
    const caseId = decodeURIComponent(rawCaseId);

    async function loadCase() {
      setLoading(true);
      try {
        const res = await getCaseDetail(caseId);
        if (res && (res.analysis || res.analysis_report)) {
          setData(res.analysis || res.analysis_report);
        } else {
          const local = getAnalysis(caseId);
          if (local) {
            setData(local);
          } else {
            setNotFound(true);
          }
        }
      } catch {
        const local = getAnalysis(caseId);
        if (local) setData(local);
        else setNotFound(true);
      } finally {
        setLoading(false);
      }
    }

    loadCase();
  }, [params?.caseId]);

  if (notFound) {
    return (
      <div className="flex items-center justify-center min-h-[60vh] px-4">
        <div className="glass-card p-8 max-w-md text-center space-y-4">
          <ShieldAlert className="w-12 h-12 mx-auto text-rose-500" />
          <h2 className="text-lg font-bold text-[var(--text-primary)]">Relay Map Unavailable</h2>
          <p className="text-xs text-[var(--text-secondary)]">
            Case <code className="mono text-[var(--primary-cyan)] font-bold">{params?.caseId}</code> was not found in active database records.
          </p>
          <Link
            href="/cases"
            className="btn-cyber-primary inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold"
          >
            Go to Cases
          </Link>
        </div>
      </div>
    );
  }

  if (loading || !data) {
    return (
      <div className="flex items-center justify-center min-h-[60vh] text-[var(--primary-cyan)] text-sm">
        <div className="w-6 h-6 border-2 border-[var(--primary-cyan)] border-t-transparent rounded-full animate-spin mr-3" />
        <span>Loading delivery route...</span>
      </div>
    );
  }

  const hops = data.relay_path || [];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-16 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <button
            onClick={() => router.back()}
            className="flex items-center gap-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--primary-cyan)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] rounded px-1 -ml-1 transition-colors mb-2 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Report
          </button>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--text-primary)]">
              Delivery Route: <span className="mono">{data.case_id}</span>
            </h1>
            <span className="badge text-[10px] bg-[var(--primary-cyan)]/10 text-[var(--primary-cyan)] border border-[var(--border-cyan)] font-semibold">
              {hops.length} Hops
            </span>
          </div>
        </div>

        <Link
          href={`/report/${encodeURIComponent(data.case_id)}`}
          className="btn-cyber-primary flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold shadow-md self-start sm:self-auto"
        >
          <FileText className="w-3.5 h-3.5" />
          <span>View Report</span>
        </Link>
      </div>

      {/* Map + Side Hop Explorer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[72vh] min-h-[500px]">
        {/* Fullscreen Map Canvas */}
        <div className="lg:col-span-2 glass-card overflow-hidden border border-[var(--border-cyan)] shadow-lg">
          <RelayMapInner relayPath={hops} />
        </div>

        {/* Sidebar Hop Breakdown */}
        <div className="glass-card p-5 overflow-y-auto space-y-3 text-xs">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
            <span className="font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
              <Route className="w-4 h-4 text-[var(--primary-cyan)]" />
              <span>Hop Sequence</span>
            </span>
            <span className="text-[11px] mono text-[var(--text-muted)]">{hops.length} Total</span>
          </div>

          {hops.map((hop, idx) => (
            <div
              key={idx}
              className="p-3 rounded-xl bg-[var(--surface-container-low)] border border-[var(--border-subtle)] hover:border-[var(--border-cyan)] transition-all space-y-1"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-[var(--primary-cyan)]">
                  Hop #{hop.hop_number || idx + 1}
                </span>
                <span className="text-[10px] mono text-[var(--text-muted)]">
                  {hop.ip_type || (hop.is_private_ip ? 'RFC1918' : 'Public')}
                </span>
              </div>

              {hop.ip && (
                <div className="text-[11px]">
                  <span className="text-[var(--text-muted)]">IP:</span>{' '}
                  <span className="mono text-[var(--text-primary)] font-medium">{hop.ip}</span>
                </div>
              )}

              {hop.from_host && (
                <div className="text-[10px] mono text-[var(--text-secondary)] truncate">
                  From: {hop.from_host}
                </div>
              )}

              {hop.by_host && (
                <div className="text-[10px] mono text-[var(--text-secondary)] truncate">
                  By: {hop.by_host}
                </div>
              )}

              {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                <div className="text-[10px] text-amber-500 font-medium pt-0.5 mono">
                  +{hop.delay_seconds}s latency
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
