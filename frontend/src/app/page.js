'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  FileText,
  ShieldAlert,
  Activity,
  ArrowRight,
  RefreshCw,
  PlusCircle,
  Search,
  Upload,
  Database,
} from 'lucide-react';
import { getHistory } from '@/lib/storage';
import { listCases, checkHealth } from '@/lib/api';

export default function DashboardPage() {
  const [cases, setCases] = useState([]);
  const [health, setHealth] = useState({ status: 'checking' });
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');

  const loadData = async () => {
    setLoading(true);
    try {
      const [backendCases, healthRes] = await Promise.all([
        listCases(50, 0),
        checkHealth(),
      ]);

      setHealth(healthRes || { status: 'offline' });

      if (backendCases && backendCases.cases && backendCases.cases.length > 0) {
        const formatted = backendCases.cases.map((c) => ({
          case_id: c.case_id,
          subject: c.original_filename || 'Email analysis',
          risk_score: c.risk_score,
          risk_classification: c.classification,
          timestamp: c.created_at,
          file_name: c.original_filename,
          file_size: c.file_size,
        }));
        setCases(formatted);
      } else {
        setCases(getHistory());
      }
    } catch {
      setCases(getHistory());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const totalCases = cases.length;
  const criticalThreats = cases.filter(
    (c) =>
      c.risk_score >= 60 ||
      (c.risk_classification && c.risk_classification.toUpperCase().includes('CRITICAL'))
  ).length;
  const highRiskThreats = cases.filter(
    (c) => c.risk_score >= 35 && c.risk_score < 60
  ).length;
  const avgRiskScore =
    totalCases > 0
      ? Math.round(cases.reduce((acc, c) => acc + (c.risk_score || 0), 0) / totalCases)
      : 0;

  const filteredCases = cases.filter((c) => {
    const matchesSearch =
      !searchQuery ||
      c.case_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.subject?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.file_name?.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;
    if (riskFilter === 'ALL') return true;
    if (riskFilter === 'CRITICAL') return c.risk_score >= 60;
    if (riskFilter === 'HIGH') return c.risk_score >= 35 && c.risk_score < 60;
    if (riskFilter === 'CLEAN') return c.risk_score < 35;
    return true;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-16">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between pb-6 mb-8 border-b border-[var(--border-subtle)] gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--text-primary)]">
            Email Analysis
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Analyze email headers, authentication, and content for phishing threats.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-[var(--border-subtle)] bg-[var(--surface-container-low)] text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                health.status === 'online' ? 'bg-emerald-500' : 'bg-rose-500'
              }`}
            />
            <span className="text-[var(--text-secondary)]">
              {health.status === 'online' ? 'Backend online' : 'Backend offline'}
            </span>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="p-2 rounded-md border border-[var(--border-subtle)] bg-[var(--surface-container-low)] hover:bg-[var(--surface-container-high)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
            title="Refresh cases"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>

          <Link
            href="/analyze"
            className="btn-cyber-primary px-4 py-2 rounded-xl text-xs shadow-sm"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Analyze Email</span>
          </Link>
        </div>
      </div>

      {/* Stats bar - real numbers only */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div className="glass-panel p-5 rounded-lg border border-[var(--border-subtle)]">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)] mb-2">
            <span>Total cases</span>
            <FileText className="w-4 h-4 text-[var(--text-muted)]" />
          </div>
          <div className="text-3xl font-bold text-[var(--text-primary)]">
            {totalCases}
          </div>
        </div>

        <div className="glass-panel p-5 rounded-lg border border-[var(--border-subtle)]">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)] mb-2">
            <span>Critical</span>
            <ShieldAlert className="w-4 h-4 text-[var(--accent-red)]" />
          </div>
          <div className="text-3xl font-bold text-[var(--accent-red)]">
            {criticalThreats}
          </div>
        </div>

        <div className="glass-panel p-5 rounded-lg border border-[var(--border-subtle)]">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)] mb-2">
            <span>High risk</span>
            <Activity className="w-4 h-4 text-[var(--accent-amber)]" />
          </div>
          <div className="text-3xl font-bold text-[var(--accent-amber)]">
            {highRiskThreats}
          </div>
        </div>

        <div className="glass-panel p-5 rounded-lg border border-[var(--border-subtle)]">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)] mb-2">
            <span>Average risk</span>
            <Database className="w-4 h-4 text-[var(--text-muted)]" />
          </div>
          <div className="text-3xl font-bold text-[var(--text-primary)]">
            {avgRiskScore}
            <span className="text-xs text-[var(--text-muted)] font-normal ml-1">/ 100</span>
          </div>
        </div>
      </div>

      {/* Empty state */}
      {cases.length === 0 ? (
        <div className="glass-panel rounded-lg border border-[var(--border-subtle)] py-16 px-6 text-center">
          <div className="w-14 h-14 mx-auto rounded-full bg-[var(--surface-container-high)] flex items-center justify-center mb-4">
            <Upload className="w-6 h-6 text-[var(--text-muted)]" />
          </div>
          <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-1">
            No emails analyzed yet
          </h2>
          <p className="text-sm text-[var(--text-secondary)] mb-6">
            Upload your first .eml file to get started.
          </p>
          <Link
            href="/analyze"
            className="btn-cyber-primary inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs shadow-sm"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Upload an email</span>
          </Link>
        </div>
      ) : (
        <div className="glass-panel rounded-lg border border-[var(--border-subtle)]">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 pb-4 border-b border-[var(--border-subtle)] px-6 pt-6">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Recent cases
              </h2>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                {totalCases} total, stored locally in SQLite
              </p>
            </div>

            <div className="flex items-center gap-3 flex-wrap">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
                <input
                  type="text"
                  placeholder="Search case ID or subject..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="cyber-input pl-8 pr-3 py-1.5 w-52 sm:w-64 text-xs"
                />
              </div>

              <div className="flex items-center gap-1 text-xs">
                {['ALL', 'CRITICAL', 'HIGH', 'CLEAN'].map((tier) => (
                  <button
                    key={tier}
                    onClick={() => setRiskFilter(tier)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-cyan)] ${
                      riskFilter === tier
                        ? 'bg-[var(--primary-cyan)] text-[#05070b]'
                        : 'border border-[var(--border-subtle)] text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    {tier}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="overflow-x-auto px-6 pb-6">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-[var(--text-muted)] text-[11px]">
                  <th className="py-2.5 px-3">Case ID</th>
                  <th className="py-2.5 px-3">Subject / File</th>
                  <th className="py-2.5 px-3">Risk level</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {filteredCases.length > 0 ? (
                  filteredCases.map((c) => {
                    const isCrit = c.risk_score >= 60;
                    const isHigh = c.risk_score >= 35 && c.risk_score < 60;
                    const safeScore = c.risk_score ?? 0;
                    const classification =
                      c.risk_classification || (isCrit ? 'CRITICAL' : isHigh ? 'HIGH' : 'CLEAN');
                    return (
                      <tr key={c.case_id} className="hover:bg-[var(--surface-container-high)]/40 transition-colors">
                        <td className="py-3 px-3 mono font-bold text-[var(--text-primary)] whitespace-nowrap">
                          {c.case_id}
                        </td>
                        <td className="py-3 px-3 text-[var(--text-primary)] max-w-md truncate">
                          {c.subject || c.file_name || c.case_id}
                        </td>
                        <td className="py-3 px-3 whitespace-nowrap">
                          <span
                            className={`mono text-[10px] font-bold px-2 py-0.5 rounded border ${
                              isCrit
                                ? 'bg-[var(--accent-red)]/15 text-[var(--accent-red)] border-[var(--accent-red)]/30'
                                : isHigh
                                ? 'bg-[var(--accent-amber)]/15 text-[var(--accent-amber)] border-[var(--accent-amber)]/30'
                                : 'bg-[var(--accent-green)]/15 text-[var(--accent-green)] border-[var(--accent-green)]/30'
                            }`}
                          >
                            {safeScore}/100 • {classification}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-[var(--text-muted)] whitespace-nowrap">
                          {c.timestamp ? new Date(c.timestamp).toLocaleDateString() : 'N/A'}
                        </td>
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          <Link
                            href={`/report/${c.case_id}`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[var(--surface-container-high)] text-[var(--text-primary)] border border-[var(--border-subtle)] text-[11px] font-bold transition-colors hover:border-[var(--primary-cyan)]"
                          >
                            <span>View report</span>
                            <ArrowRight className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-[var(--text-muted)] text-xs">
                      No cases match the current search or filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}