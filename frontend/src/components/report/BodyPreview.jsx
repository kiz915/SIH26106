'use client';

import { useState } from 'react';
import { FileText, Copy, CheckCheck, Eye, ShieldCheck } from 'lucide-react';

export default function BodyPreview({ bodyPreview }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!bodyPreview) return;
    try {
      await navigator.clipboard.writeText(bodyPreview);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Ignore
    }
  };

  return (
    <div className="glass-card p-5 h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-[var(--primary-cyan)]" />
            <h3 className="text-sm font-bold font-mono text-[var(--text-primary)]">
              Sanitized Body Content Preview
            </h3>
          </div>
          {bodyPreview && (
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 text-[11px] font-mono font-bold text-[var(--primary-cyan)] hover:underline transition-colors"
            >
              {copied ? <CheckCheck className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Text'}</span>
            </button>
          )}
        </div>

        <div className="p-4 rounded-xl bg-[var(--surface-container-low)] border border-[var(--border-subtle)] text-xs font-mono text-[var(--text-primary)] max-h-60 overflow-y-auto whitespace-pre-wrap leading-relaxed select-text shadow-inner">
          {bodyPreview || '(No plain-text body content parsed from payload)'}
        </div>
      </div>
      <p className="text-[10px] text-[var(--text-muted)] font-mono mt-3 flex items-center gap-1.5">
        <ShieldCheck className="w-3.5 h-3.5 text-[var(--primary-cyan)] shrink-0" />
        <span>Active scripts, malicious iframes, and remote trackers were neutralized during ingestion.</span>
      </p>
    </div>
  );
}
