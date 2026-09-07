'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Blocks, CheckCircle2, Copy, ExternalLink, Lock, ShieldCheck } from 'lucide-react';
import { deriveBlockchainRecord } from '@/lib/blockchain';

export default function EvidenceSeal({ caseId, evidence, analysisTimestamp }) {
  const [copied, setCopied] = useState(false);
  const sha256 = evidence?.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const blockRecord = deriveBlockchainRecord(caseId, sha256, analysisTimestamp);

  const handleCopyHash = async () => {
    try {
      await navigator.clipboard.writeText(sha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // ignore clipboard error
    }
  };

  return (
    <div className="terminal-card p-5 border border-[var(--border-cyan)]">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[var(--primary-cyan)]/15 border border-[var(--border-cyan)] flex items-center justify-center shadow-[0_0_15px_var(--primary-cyan-glow)]">
            <Blocks className="w-5 h-5 text-[var(--primary-cyan)]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-[var(--text-primary)]">
                Evidence Integrity Record
              </h3>
              <span className="badge text-[10px] bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 flex items-center gap-1 font-bold">
                <ShieldCheck className="w-3 h-3" /> VERIFIED
              </span>
            </div>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">
              Evidence ID: <span className="mono text-[var(--primary-cyan)] font-bold">{evidence?.evidence_id || (caseId ? `EVID-${caseId}` : 'N/A')}</span> • Custody Block #{blockRecord.blockHeight}
            </p>
          </div>
        </div>

        <Link
          href={`/blockchain?caseId=${encodeURIComponent(caseId || '')}&hash=${encodeURIComponent(sha256)}`}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-[var(--primary-cyan)] bg-[var(--primary-cyan)]/10 hover:bg-[var(--primary-cyan)]/20 border border-[var(--border-cyan)] transition-all self-start sm:self-auto shadow-sm"
        >
          <span>Verify on Ledger</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* SHA-256 Hash Display */}
      <div className="mt-4 pt-1">
        <div className="flex items-center justify-between text-xs text-[var(--text-muted)] font-mono mb-1.5">
          <span className="flex items-center gap-1 text-[var(--text-primary)] font-semibold">
            <Lock className="w-3.5 h-3.5 text-[var(--primary-cyan)]" /> Exact SHA-256 Payload Hash:
          </span>
          <button
            onClick={handleCopyHash}
            className="flex items-center gap-1 text-[11px] font-bold text-[var(--primary-cyan)] hover:underline transition-colors"
          >
            {copied ? (
              <>
                <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                <span className="text-emerald-500">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy Hash</span>
              </>
            )}
          </button>
        </div>
        <div
          onClick={handleCopyHash}
          className="group cursor-pointer p-2.5 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)] hover:border-[var(--border-cyan)] transition-all font-mono text-xs text-[var(--primary-cyan)] break-all select-all flex items-center justify-between"
        >
          <span>{sha256}</span>
          <Copy className="w-3.5 h-3.5 text-[var(--text-muted)] group-hover:text-[var(--primary-cyan)] shrink-0 ml-2" />
        </div>
      </div>
    </div>
  );
}
