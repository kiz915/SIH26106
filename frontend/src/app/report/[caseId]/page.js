'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  ArrowLeft,
  Download,
  Clock,
  FileText,
  MapPin,
  Printer,
  ShieldAlert,
  Blocks,
  BrainCircuit,
  Share2,
  Lock,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
  Zap
} from 'lucide-react';
import Link from 'next/link';
import { getAnalysis } from '@/lib/storage';
import { getCaseDetail, getCaseEvidence } from '@/lib/api';
import RiskGauge from '@/components/report/RiskGauge';
import AuthBadges from '@/components/report/AuthBadges';
import EmailMeta from '@/components/report/EmailMeta';
import SignalTable from '@/components/report/SignalTable';
import BodyPreview from '@/components/report/BodyPreview';
import IOCPanel from '@/components/report/IOCPanel';
import RelayTimeline from '@/components/report/RelayTimeline';
import EvidenceSeal from '@/components/report/EvidenceSeal';
import IntelPanel from '@/components/report/IntelPanel';
import MLInsightCard from '@/components/report/MLInsightCard';

export default function ReportPage() {
  const params = useParams();
  const router = useRouter();
  const [data, setData] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    const rawCaseId = params?.caseId;
    if (!rawCaseId) return;
    const caseId = decodeURIComponent(rawCaseId);

    async function loadReport() {
      setLoading(true);
      try {
        const [caseRes, evidRes] = await Promise.all([
          getCaseDetail(caseId),
          getCaseEvidence(caseId),
        ]);

        if (caseRes && (caseRes.analysis || caseRes.analysis_report)) {
          setData(caseRes.analysis || caseRes.analysis_report);
          setEvidence(caseRes.evidence || evidRes);
        } else {
          const localData = getAnalysis(caseId);
          if (localData) {
            setData(localData);
            setEvidence(evidRes || {
              case_id: localData.case_id,
              sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              evidence_id: `EVID-${localData.case_id}`,
              original_filename: localData.metadata?.file_name || 'email.eml',
              file_size: localData.metadata?.file_size_bytes || 4096,
              collected_at: localData.metadata?.analysis_timestamp || new Date().toISOString(),
              storage_reference: 'local-browser-cache',
            });
          } else {
            setNotFound(true);
          }
        }
      } catch (err) {
        console.warn('Report loading error:', err);
        const localData = getAnalysis(caseId);
        if (localData) {
          setData(localData);
        } else {
          setNotFound(true);
        }
      } finally {
        setLoading(false);
      }
    }

    loadReport();
  }, [params.caseId]);

  const handleExportJSON = () => {
    if (!data) return;
    const payload = {
      ...data,
      evidence_proof: evidence,
      exported_at: new Date().toISOString(),
      standard: 'NIST SP 800-86 / SIH26106 Forensic Spec',
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ThreatLens-Forensics-${data.case_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  if (notFound) {
    return (
      <div className="flex items-center justify-center min-h-[60vh] px-4">
        <div className="glass-card p-8 max-w-md text-center">
          <ShieldAlert className="w-12 h-12 mx-auto mb-3 text-rose-500" />
          <h2 className="text-lg font-bold text-[var(--text-primary)] mb-2">Case Not Found</h2>
          <p className="text-xs text-[var(--text-secondary)] mb-6">
            Case identifier <code className="mono text-[var(--primary-cyan)] font-bold">{params?.caseId}</code> was not located in active database records.
          </p>
          <Link
            href="/analyze"
            className="btn-cyber-primary inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold shadow-md"
          >
            Analyze Email
          </Link>
        </div>
      </div>
    );
  }

  if (loading || !data) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center space-y-3">
          <div className="w-10 h-10 border-2 border-[var(--primary-cyan)] border-t-transparent rounded-full animate-spin mx-auto shadow-[0_0_15px_var(--primary-cyan-glow)]" />
          <p className="text-sm text-[var(--primary-cyan)] font-medium">Loading case report...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-16 space-y-6">
      {/* Top Header with Navigation & Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]"
      >
        <div>
          <button
            onClick={() => router.back()}
            className="flex items-center gap-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--primary-cyan)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] rounded px-1 -ml-1 transition-colors mb-2 no-print cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Cases
          </button>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--text-primary)] mono">
              {data.case_id}
            </h1>
            <span className="badge text-[10px] bg-[var(--primary-cyan)]/10 text-[var(--primary-cyan)] border border-[var(--border-cyan)] font-bold">
              ANALYSIS REPORT
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1.5 text-xs text-[var(--text-secondary)]">
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              {data.metadata?.analysis_timestamp ? new Date(data.metadata.analysis_timestamp).toLocaleString() : 'N/A'}
            </span>
            <span className="flex items-center gap-1">
              <FileText className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              {data.metadata?.file_name || 'email.eml'}
            </span>
            {data.metadata?.execution_time_ms && (
              <span className="text-[var(--primary-cyan)] font-semibold flex items-center gap-1">
                <Zap className="w-3.5 h-3.5 text-[var(--primary-cyan)]" />
                <span className="mono">{data.metadata.execution_time_ms}ms execution</span>
              </span>
            )}
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2 no-print">
          {data.relay_path?.length > 0 && (
            <Link
              href={`/map/${encodeURIComponent(data.case_id)}`}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-[var(--primary-cyan)] bg-[var(--primary-cyan)]/10 hover:bg-[var(--primary-cyan)]/20 active:scale-[0.98] border border-[var(--border-cyan)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] transition-all shadow-sm"
            >
              <MapPin className="w-4 h-4 text-[var(--primary-cyan)]" />
              <span>Delivery Route Map</span>
            </Link>
          )}
          <Link
            href={`/blockchain?caseId=${encodeURIComponent(data.case_id)}&hash=${encodeURIComponent(evidence?.sha256 || '')}`}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-amber-600 dark:text-amber-400 bg-amber-500/10 hover:bg-amber-500/20 active:scale-[0.98] border border-amber-500/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500 transition-all shadow-sm"
          >
            <Blocks className="w-4 h-4 text-amber-500" />
            <span>Ledger Record</span>
          </Link>
          <button
            onClick={handleExportJSON}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-[var(--text-primary)] bg-[var(--surface-container-low)] hover:bg-[var(--surface-container)] active:scale-[0.98] border border-[var(--border-subtle)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] transition-all shadow-sm cursor-pointer"
            title="Download Forensic JSON"
          >
            <Download className="w-4 h-4 text-[var(--text-muted)]" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-[var(--text-primary)] bg-[var(--surface-container-low)] hover:bg-[var(--surface-container)] active:scale-[0.98] border border-[var(--border-subtle)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] transition-all shadow-sm cursor-pointer"
            title="Print or Save as PDF"
          >
            <Printer className="w-4 h-4 text-[var(--text-muted)]" />
            <span>Print Report</span>
          </button>
        </div>
      </motion.div>

      {/* Cryptographic Evidence Seal Banner */}
      <EvidenceSeal
        caseId={data.case_id}
        evidence={evidence}
        analysisTimestamp={data.metadata?.analysis_timestamp}
      />

      {/* Risk Gauge + Authentication Protocols */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
          className="glass-card p-6 flex flex-col items-center justify-center text-center shadow-lg"
        >
          <RiskGauge score={data.risk?.score} classification={data.risk?.classification} />
          <p className="text-[11px] font-mono text-[var(--text-muted)] mt-2">
            Engine: <span className="text-[var(--primary-cyan)] font-bold">{data.risk?.scoring_type || 'Deterministic Rule Pipeline'}</span>
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.15 }}
          className="lg:col-span-2"
        >
          <AuthBadges authentication={data.authentication} />
        </motion.div>
      </div>

      {/* AI/ML Threat Assessment & NLP Insight */}
      <MLInsightCard
        mlSignals={data.risk?.ml_signals}
        emailText={`${data.email?.subject || ''} ${data.email?.body_preview || ''}`}
      />

      {/* Triggered Signals Table */}
      <SignalTable signals={data.risk?.signals} />

      {/* Email Metadata + Content Body Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <EmailMeta email={data.email} />
        <BodyPreview bodyPreview={data.email?.body_preview} />
      </div>

      {/* Extracted IOCs & Forensic Intel Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <IOCPanel iocs={data.iocs} />
        <IntelPanel iocs={data.iocs} />
      </div>

      {/* Interactive Hop-by-Hop Relay Timeline */}
      <RelayTimeline relayPath={data.relay_path} />
    </div>
  );
}
