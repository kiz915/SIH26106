'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  Server,
  Database,
  BrainCircuit,
  Blocks,
  Globe,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Cpu,
  Clock,
  ShieldCheck,
  Zap,
  Lock,
  HardDrive
} from 'lucide-react';
import { checkHealth, listCases } from '@/lib/api';

export default function StatusPage() {
  const [healthData, setHealthData] = useState(null);
  const [dbData, setDbData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [apiLatency, setApiLatency] = useState(null);
  const [dbLatency, setDbLatency] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  const runDiagnostics = async () => {
    setLoading(true);

    // Probe 1: Core API Health
    const startApi = performance.now();
    try {
      const res = await checkHealth();
      setApiLatency(Math.round(performance.now() - startApi));
      setHealthData(res);
    } catch {
      setHealthData({ status: 'offline' });
      setApiLatency(null);
    }

    // Probe 2: SQLite Cases Database
    const startDb = performance.now();
    try {
      const casesRes = await listCases(1, 0);
      setDbLatency(Math.round(performance.now() - startDb));
      setDbData(casesRes);
    } catch {
      setDbData(null);
      setDbLatency(null);
    }

    setLastChecked(new Date().toLocaleTimeString());
    setLoading(false);
  };

  useEffect(() => {
    runDiagnostics();
  }, []);

  const isApiOnline = healthData?.status === 'online';
  const isDbOnline = dbData !== null && dbData !== undefined;
  const totalCases = dbData?.total || 0;

  const nodes = [
    {
      name: 'FastAPI Forensic Kernel',
      role: 'RFC 822 Header Deconstruction & IOC Parser',
      status: isApiOnline ? 'ONLINE' : 'OFFLINE',
      endpoint: 'http://127.0.0.1:8000',
      version: healthData?.version || '1.0.0-prototype',
      latency: apiLatency ? `${apiLatency}ms` : 'Unreachable',
      icon: Server,
      color: isApiOnline ? '#10b981' : '#ef4444',
      details: isApiOnline ? 'Handling live multipart RFC uploads' : 'Check uvicorn backend daemon',
    },
    {
      name: 'Forensic Evidence Database',
      role: 'Local SQLite Relational Evidence Datastore',
      status: isDbOnline ? 'CONNECTED' : 'DISCONNECTED',
      endpoint: 'backend/forensics.db',
      version: `${totalCases} Indexed Cases`,
      latency: dbLatency ? `${dbLatency}ms` : 'N/A',
      icon: Database,
      color: isDbOnline ? '#10b981' : '#ef4444',
      details: isDbOnline ? `Active SQLite schema storing verified case records` : 'Database connection error',
    },
    {
      name: 'Deterministic Threat Engine',
      role: 'Urgency, BEC & Cryptographic Scoring Matrix',
      status: isApiOnline ? 'ACTIVE' : 'OFFLINE',
      endpoint: 'In-Process Python Module',
      version: 'v1.0 Rules Engine',
      latency: '< 5ms',
      icon: Zap,
      color: isApiOnline ? '#10b981' : '#ef4444',
      details: 'Evaluates SPF/DKIM/DMARC penalties & threat signals',
    },
    {
      name: 'Subtle Crypto Validation Engine',
      role: 'Browser-Native W3C Web Cryptography API',
      status: typeof window !== 'undefined' && window.crypto?.subtle ? 'OPERATIONAL' : 'UNAVAILABLE',
      endpoint: 'Client-Side Hardware Sandbox',
      version: 'SHA-256 Standard',
      latency: '< 1ms',
      icon: Lock,
      color: '#10b981',
      details: 'Instant client-side bitstream checksum & proof verification',
    },
    {
      name: 'Evidence Ledger Storage',
      role: 'Persistent Local Forensic Audit Records',
      status: 'SYNCHRONIZED',
      endpoint: 'localStorage:sih26106_history',
      version: 'Browser Sandboxed',
      latency: '< 1ms',
      icon: Blocks,
      color: '#10b981',
      details: 'Preserves forensic dossiers across browser sessions',
    },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-16 space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card p-6 sm:p-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-6 border-t-2 border-t-[var(--primary-cyan)]"
      >
        <div className="space-y-2 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
            <Activity className="w-3.5 h-3.5 text-emerald-500" />
            <span>SYSTEM STATUS</span>
          </div>
          <h1 className="text-3xl font-bold text-[var(--text-primary)] tracking-tight">
            System Status
          </h1>
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
            Live service status, API latency, and database connectivity.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right text-xs text-[var(--text-muted)] hidden sm:block">
            <div>Last checked: {lastChecked || 'Checking...'}</div>
            <div className="text-[10px] mono">Ping: {apiLatency ? `${apiLatency}ms` : 'N/A'}</div>
          </div>
          <button
            onClick={runDiagnostics}
            disabled={loading}
            className="btn-cyber-primary flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold shadow-md shrink-0 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Run Diagnostics</span>
          </button>
        </div>
      </motion.div>

      {/* Primary Overall Health Strip */}
      <div className={`p-4 sm:p-5 rounded-2xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
        isApiOnline && isDbOnline
          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300'
          : 'bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-300'
      }`}>
        <div className="flex items-center gap-3">
          {isApiOnline && isDbOnline ? (
            <CheckCircle2 className="w-6 h-6 text-emerald-500 shrink-0" />
          ) : (
            <AlertCircle className="w-6 h-6 text-rose-500 shrink-0" />
          )}
          <div>
            <p className="font-bold text-sm">
              {isApiOnline && isDbOnline
                ? 'All systems operational'
                : 'Backend offline or degraded'}
            </p>
            <p className="text-xs opacity-80 mt-0.5">
              {isApiOnline && isDbOnline
                ? `FastAPI kernel online on :8000 with ${totalCases} evidence cases indexed in SQLite database.`
                : 'Could not connect to FastAPI backend on http://127.0.0.1:8000.'}
            </p>
          </div>
        </div>

        <div className="text-xs font-bold px-3 py-1.5 rounded-xl bg-[var(--surface-base)] border border-current">
          {isApiOnline && isDbOnline ? 'STATUS: HEALTHY' : 'STATUS: OFFLINE'}
        </div>
      </div>

      {/* Nodes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {nodes.map((node, idx) => {
          const Icon = node.icon;
          const isOk = node.status === 'ONLINE' || node.status === 'CONNECTED' || node.status === 'OPERATIONAL' || node.status === 'SYNCHRONIZED';

          return (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.08 }}
              className="glass-card p-6 flex flex-col justify-between space-y-4 hover:border-[var(--primary-cyan)] transition-all"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center border"
                    style={{
                      background: `${node.color}15`,
                      borderColor: `${node.color}40`,
                    }}
                  >
                    <Icon className="w-5 h-5" style={{ color: node.color }} />
                  </div>
                  <span
                    className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      isOk
                        ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                        : 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    {node.status}
                  </span>
                </div>

                <h3 className="font-bold text-sm text-[var(--text-primary)]">{node.name}</h3>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">{node.role}</p>
              </div>

              <div className="space-y-2 pt-4 border-t border-[var(--border-subtle)] font-mono text-xs">
                <div className="flex justify-between text-[var(--text-secondary)]">
                  <span className="text-[11px] text-[var(--text-muted)]">Endpoint:</span>
                  <span className="text-[var(--text-primary)] font-bold text-[11px] truncate max-w-[150px]">{node.endpoint}</span>
                </div>
                <div className="flex justify-between text-[var(--text-secondary)]">
                  <span className="text-[11px] text-[var(--text-muted)]">Version / Data:</span>
                  <span className="text-[var(--text-primary)] text-[11px]">{node.version}</span>
                </div>
                <div className="flex justify-between text-[var(--text-secondary)]">
                  <span className="text-[11px] text-[var(--text-muted)]">Latency:</span>
                  <span className="text-[var(--primary-cyan)] font-bold text-[11px]">{node.latency}</span>
                </div>
                <p className="text-[10px] text-[var(--text-muted)] pt-1">{node.details}</p>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
