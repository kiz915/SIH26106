'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle2,
  XCircle,
  MinusCircle,
  HelpCircle,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  FileCode
} from 'lucide-react';
import { AUTH_STATUS_CONFIG } from '@/lib/constants';

const icons = {
  CheckCircle: CheckCircle2,
  XCircle,
  MinusCircle,
  HelpCircle,
};

function AuthCard({ name, status = 'UNKNOWN', subtitle }) {
  const config = AUTH_STATUS_CONFIG[status] || AUTH_STATUS_CONFIG.UNKNOWN;
  const IconComponent = icons[config.icon] || HelpCircle;

  return (
    <div
      className="p-4 rounded-xl border transition-all relative overflow-hidden bg-[var(--surface-container-low)]"
      style={{
        borderColor: config.border,
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)]">
          {name}
        </span>
        <span
          className="badge text-[11px] font-bold"
          style={{
            background: config.bg,
            color: config.color,
            borderColor: config.border,
            borderWidth: 1,
          }}
        >
          <IconComponent className="w-3.5 h-3.5" />
          {config.label}
        </span>
      </div>
      <p className="text-[11px] text-[var(--text-secondary)] leading-snug">{subtitle}</p>
    </div>
  );
}

export default function AuthBadges({ authentication }) {
  const [showRaw, setShowRaw] = useState(false);
  if (!authentication) return null;

  const { spf, dkim, dmarc, raw_results = [] } = authentication;

  return (
    <div className="glass-card p-5 h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[var(--primary-cyan)]" />
            <h3 className="text-sm font-bold text-[var(--text-primary)]">
              Email Authentication
            </h3>
          </div>
          <span className="text-[11px] text-[var(--text-muted)]">
            SPF • DKIM • DMARC
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <AuthCard
            name="SPF Check"
            status={spf}
            subtitle={
              spf === 'PASS'
                ? 'Origin IP authorized by sender domain SPF DNS record.'
                : spf === 'FAIL'
                ? 'Transmitting server IP is NOT authorized in domain SPF record.'
                : 'No SPF record or indeterminate status.'
            }
          />
          <AuthCard
            name="DKIM Signature"
            status={dkim}
            subtitle={
              dkim === 'PASS'
                ? 'Cryptographic digital signature verified against public key.'
                : dkim === 'FAIL'
                ? 'DKIM signature invalid or payload altered in transit.'
                : 'No cryptographic DKIM header found.'
            }
          />
          <AuthCard
            name="DMARC Policy"
            status={dmarc}
            subtitle={
              dmarc === 'PASS'
                ? 'Sender domain aligned with SPF/DKIM authentication.'
                : dmarc === 'FAIL'
                ? 'Sender failed alignment policy (Spoofing indicator).'
                : 'No DMARC enforcement policy published.'
            }
          />
        </div>
      </div>

      {/* Raw Authentication-Results Drawer */}
      {raw_results.length > 0 && (
        <div className="mt-4 pt-3 border-t border-[var(--border-subtle)]">
          <button
            onClick={() => setShowRaw(!showRaw)}
            className="w-full flex items-center justify-between text-xs font-mono text-[var(--text-secondary)] hover:text-[var(--primary-cyan)] transition-colors"
          >
            <span className="flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-[var(--primary-cyan)]" />
              <span>Raw Authentication-Results Headers ({raw_results.length})</span>
            </span>
            {showRaw ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          <AnimatePresence>
            {showRaw && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mt-3 space-y-2 overflow-hidden"
              >
                {raw_results.map((r, i) => (
                  <pre
                    key={i}
                    className="p-3 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)] text-[11px] font-mono text-[var(--text-secondary)] overflow-x-auto whitespace-pre-wrap leading-relaxed"
                  >
                    {r}
                  </pre>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}
