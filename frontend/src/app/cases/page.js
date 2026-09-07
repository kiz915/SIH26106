'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  FolderArchive,
  Search,
  Filter,
  Trash2,
  Clock,
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  FileSearch,
  ExternalLink,
  Blocks,
  Download,
  RefreshCw,
  Paperclip,
  Activity,
  ShieldAlert,
  CheckCircle2,
  Database
} from 'lucide-react';
import { listCases } from '@/lib/api';
import { getHistory, clearHistory } from '@/lib/storage';
import { RISK_TIERS } from '@/lib/constants';

export default function CasesPage() {
  const [cases, setCases] = useState([]);
  const [search, setSearch] = useState('');
  const [filterTier, setFilterTier] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const fetchCaseList = async () => {
    setLoading(true);
    try {
      const res = await listCases(100, 0);
      if (res && res.cases && res.cases.length > 0) {
        const formatted = res.cases.map(c => ({
          case_id: c.case_id,
          subject: c.original_filename || 'Email Forensic Analysis',
          from: 'Uploaded EML',
          risk_score: c.risk_score,
          risk_classification: c.classification,
          timestamp: c.created_at,
          file_name: c.original_filename,
          file_size: c.file_size,
          status: c.status,
        }));
        setCases(formatted);
      } else {
        setCases(getHistory());
      }
    } catch (err) {
      console.warn('Fallback to local storage:', err);
      setCases(getHistory());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCaseList();
  }, []);

  const handleClearLocal = () => {
    if (confirm('Purge local browser case records? (Server SQLite records remain intact)')) {
      clearHistory();
      fetchCaseList();
    }
  };

  const filtered = cases.filter(entry => {
    const term = search.toLowerCase();
    const matchesSearch =
      !search ||
      entry.case_id?.toLowerCase().includes(term) ||
      entry.subject?.toLowerCase().includes(term) ||
      entry.from?.toLowerCase().includes(term) ||
      entry.file_name?.toLowerCase().includes(term);

    const matchesTier = filterTier === 'ALL' || entry.risk_classification === filterTier;
    return matchesSearch && matchesTier;
  });

  // Calculate live metrics for the Hero Lead
  const totalCount = cases.length;
  const criticalHighCount = cases.filter(c => c.risk_classification === 'CRITICAL RISK' || c.risk_classification === 'HIGH RISK').length;
  const cleanCount = cases.filter(c => c.risk_classification === 'LOW RISK').length;
  const avgScore = totalCount > 0 ? Math.round(cases.reduce((acc, c) => acc + (c.risk_score || 0), 0) / totalCount) : 0;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-16 space-y-6">
      {/* Header with Title & Primary Actions */}
      <motion.div
        initial={{ opacity: 0, y: -15 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]"
      >
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-[var(--primary-cyan)]/15 border border-[var(--border-cyan)] flex items-center justify-center shadow-sm">
              <FolderArchive className="w-5 h-5 text-[var(--primary-cyan)]" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--text-primary)]">
                Cases
              </h1>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="badge text-[10px] bg-[var(--primary-cyan)]/10 text-[var(--primary-cyan)] border border-[var(--border-cyan)] font-bold">
                  {totalCount} Total Cases
                </span>
                <span className="text-[11px] text-[var(--text-muted)] flex items-center gap-1">
                  <Database className="w-3 h-3 text-[var(--primary-cyan)]" /> SQLite Storage
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchCaseList}
            disabled={loading}
            aria-busy={loading}
            className="btn-cyber-secondary px-3.5 py-2 rounded-xl text-xs"
            title="Refresh database records"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[var(--primary-cyan)]' : ''}`} />
            <span>Sync</span>
          </button>
          {cases.length > 0 && (
            <button
              onClick={handleClearLocal}
              className="btn-cyber-destructive px-3.5 py-2 rounded-xl text-xs"
              title="Clear local browser cache"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Cache</span>
            </button>
          )}
          <Link
            href="/analyze"
            className="btn-cyber-primary px-4 py-2 rounded-xl text-xs shadow-md"
          >
            <span>Analyze Email</span>
          </Link>
        </div>
      </motion.div>

      {/* Metric Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card p-4 flex items-center gap-3.5 border-l-4 border-l-[var(--primary-cyan)]">
          <div className="w-10 h-10 rounded-xl bg-[var(--primary-cyan)]/10 flex items-center justify-center shrink-0">
            <Database className="w-5 h-5 text-[var(--primary-cyan)]" />
          </div>
          <div>
            <div className="text-2xl sm:text-3xl font-black mono text-[var(--text-primary)]">
              {totalCount}
            </div>
            <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider font-semibold">
              Total Cases
            </div>
          </div>
        </div>

        <div className="glass-card p-4 flex items-center gap-3.5 border-l-4 border-l-rose-500">
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-5 h-5 text-rose-500" />
          </div>
          <div>
            <div className="text-2xl sm:text-3xl font-black mono text-rose-500">
              {criticalHighCount}
            </div>
            <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider font-semibold">
              Critical / High Risk
            </div>
          </div>
        </div>

        <div className="glass-card p-4 flex items-center gap-3.5 border-l-4 border-l-emerald-500">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center shrink-0">
            <CheckCircle2 className="w-5 h-5 text-emerald-500" />
          </div>
          <div>
            <div className="text-2xl sm:text-3xl font-black mono text-emerald-500">
              {cleanCount}
            </div>
            <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider font-semibold">
              Clean / Low Risk
            </div>
          </div>
        </div>

        <div className="glass-card p-4 flex items-center gap-3.5 border-l-4 border-l-amber-500">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 flex items-center justify-center shrink-0">
            <Activity className="w-5 h-5 text-amber-500" />
          </div>
          <div>
            <div className="text-2xl sm:text-3xl font-black mono text-[var(--text-primary)]">
              {avgScore}<span className="text-xs text-[var(--text-muted)] font-normal">/100</span>
            </div>
            <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider font-semibold">
              Average Risk Score
            </div>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col md:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by Case ID, Subject, Sender, or Filename..."
            className="cyber-input pl-10 pr-4"
          />
        </div>

        <div className="flex flex-wrap gap-1.5 p-1 rounded-xl bg-[var(--surface-container-low)] border border-[var(--border-subtle)] shadow-inner">
          {['ALL', 'LOW RISK', 'MEDIUM RISK', 'HIGH RISK', 'CRITICAL RISK'].map(tier => {
            const active = filterTier === tier;
            return (
              <button
                key={tier}
                onClick={() => setFilterTier(tier)}
                aria-selected={active}
                className={`px-3 py-1.5 rounded-lg text-[11px] font-bold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] cursor-pointer ${
                  active
                    ? 'bg-[var(--surface-base)] text-[var(--primary-cyan)] border border-[var(--border-cyan)] shadow-sm'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                {tier === 'ALL' ? 'ALL' : tier.replace(' RISK', '')}
              </button>
            );
          })}
        </div>
      </div>

      {/* Case List */}
      {filtered.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <FileSearch className="w-12 h-12 mx-auto text-[var(--text-muted)] mb-3 opacity-50" />
          <p className="text-sm font-bold text-[var(--text-primary)] mb-1">
            {cases.length === 0 ? 'No cases analyzed yet.' : 'No cases match current filter criteria.'}
          </p>
          <p className="text-xs text-[var(--text-secondary)] mb-4">
            Upload an .eml email file to initiate automated analysis.
          </p>
          <Link
            href="/analyze"
            className="btn-cyber-primary inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold shadow-md"
          >
            Analyze Email
          </Link>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((item, idx) => {
            const tier = RISK_TIERS[item.risk_classification] || RISK_TIERS['LOW RISK'];
            return (
              <motion.div
                key={item.case_id || idx}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.02 }}
                className="glass-card p-4 hover:border-[var(--border-cyan)] transition-all flex flex-col md:flex-row md:items-center justify-between gap-4 group"
              >
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-[var(--primary-cyan)]">
                      {item.case_id}
                    </span>
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-[var(--surface-container)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                      {item.status || 'ANALYZED'}
                    </span>
                    {item.file_size && (
                      <span className="text-[10px] font-mono text-[var(--text-muted)]">
                        ( {(item.file_size / 1024).toFixed(1)} KB )
                      </span>
                    )}
                  </div>

                  <h3 className="text-sm font-bold text-[var(--text-primary)] truncate">
                    {item.subject || 'No Subject Specified'}
                  </h3>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[var(--text-secondary)]">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-[var(--text-muted)]" />
                      {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'N/A'}
                    </span>
                    {item.file_name && (
                      <span className="truncate max-w-xs flex items-center gap-1">
                        <Paperclip className="w-3 h-3 text-[var(--text-muted)]" />
                        <span>{item.file_name}</span>
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 self-start md:self-center">
                  <div className="text-right">
                    <span className="text-xl mono font-black block" style={{ color: tier.color }}>
                      {item.risk_score}
                    </span>
                    <span className="text-[9px] text-[var(--text-muted)] uppercase font-bold">SCORE</span>
                  </div>

                  <span
                    className="badge text-[10px] font-bold"
                    style={{
                      background: tier.bg,
                      color: tier.color,
                      borderColor: tier.border,
                      borderWidth: 1,
                    }}
                  >
                    {tier.label}
                  </span>

                  <Link
                    href={`/report/${encodeURIComponent(item.case_id)}`}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-[var(--text-primary)] bg-[var(--surface-container-high)] hover:border-[var(--primary-cyan)] border border-[var(--border-subtle)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] transition-all shadow-sm cursor-pointer"
                  >
                    <span>View Report</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}
