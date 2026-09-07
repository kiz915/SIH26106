'use client';

import { BrainCircuit, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function MLInsightCard({ mlSignals, emailText }) {
  const modelName = mlSignals?.model || 'ThreatLens-Model-Not-Available';
  const classification = mlSignals?.classification || 'PENDING / CLEAN';
  const confidence = mlSignals?.confidence ?? 0;
  const explanation = mlSignals?.explanation || 'No machine learning signals were generated for this sample.';

  const isPhishing = classification?.toLowerCase().includes('phishing') || classification?.toLowerCase().includes('bec');

  return (
    <div className="glass-card p-5 border border-indigo-500/20 relative overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
            <BrainCircuit className="w-4 h-4 text-indigo-500" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">
              Language Model Threat Assessment
            </h3>
            <p className="text-[11px] text-[var(--text-muted)]">
              Model: <span className="mono text-indigo-500 font-medium">{modelName}</span>
            </p>
          </div>
        </div>

        <span
          className={`badge text-xs font-semibold ${
            isPhishing
              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
              : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
          }`}
        >
          {isPhishing ? <AlertTriangle className="w-3.5 h-3.5" /> : <ShieldCheck className="w-3.5 h-3.5" />}
          {classification}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 my-3">
        <div className="p-3 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)]">
          <span className="text-[11px] text-[var(--text-muted)] block font-medium">Confidence Score</span>
          <span className="text-lg font-bold mono text-[var(--primary-cyan)]">
            {Math.round(confidence * 100)}%
          </span>
        </div>
        <div className="p-3 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)]">
          <span className="text-[11px] text-[var(--text-muted)] block font-medium">Linguistic Pattern</span>
          <span className="text-sm font-semibold text-indigo-500">
            {isPhishing ? 'Adversarial Urgency' : 'Standard Baseline'}
          </span>
        </div>
        <div className="p-3 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)]">
          <span className="text-[11px] text-[var(--text-muted)] block font-medium">Flagged Keywords</span>
          <span className="text-sm font-semibold text-[var(--text-primary)]">
            {mlSignals ? 'Extracted' : '0 markers'}
          </span>
        </div>
      </div>

      <div className="p-3 rounded-lg bg-indigo-500/5 border border-indigo-500/15 text-xs text-[var(--text-secondary)]">
        <span className="text-indigo-600 dark:text-indigo-400 font-semibold block mb-1">Model Explanation:</span>
        <p className="leading-relaxed">{explanation}</p>
      </div>
    </div>
  );
}
