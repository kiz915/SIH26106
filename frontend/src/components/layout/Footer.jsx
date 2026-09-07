import Link from 'next/link';
import { Shield, Blocks, BrainCircuit, Lock, ExternalLink, Cpu } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="border-t border-white/[0.08] bg-[#07080B] text-slate-400 py-10 mt-16 relative z-10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand & Purpose */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyan-400" />
              </div>
              <span className="text-base font-bold text-white font-mono tracking-wide">
                ThreatLens Forensics
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                v1.0.0-PROTOTYPE
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-md leading-relaxed">
              Multi-engine forensic email deconstruction pipeline. Integrates RFC822 header parsing, SPF/DKIM/DMARC cryptographic validation, IP geolocation relay tracing, transformer-based AI/ML phishing inference, and blockchain proof-of-custody sealing.
            </p>
            <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500 pt-1">
              <span className="flex items-center gap-1">
                <Lock className="w-3.5 h-3.5 text-cyan-400" /> NIST SP 800-86 Compliant
              </span>
              <span className="flex items-center gap-1">
                <Blocks className="w-3.5 h-3.5 text-indigo-400" /> ISO/IEC 27037:2012
              </span>
            </div>
          </div>

          {/* Quick Engine Links */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-200 mb-3 font-mono">
              Forensic Engines
            </h4>
            <ul className="space-y-2 text-xs">
              <li>
                <Link href="/analyze" className="hover:text-cyan-300 transition-colors flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" /> EML Ingestion Pipeline
                </Link>
              </li>
              <li>
                <Link href="/ml-intelligence" className="hover:text-cyan-300 transition-colors flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" /> AI/ML RoBERTa Detection
                </Link>
              </li>
              <li>
                <Link href="/blockchain" className="hover:text-cyan-300 transition-colors flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400" /> Proof-of-Custody Ledger
                </Link>
              </li>
              <li>
                <Link href="/map" className="hover:text-cyan-300 transition-colors flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Geo-Relay Flight Tracer
                </Link>
              </li>
            </ul>
          </div>

          {/* System Telemetry */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-200 mb-3 font-mono">
              System Telemetry
            </h4>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between items-center py-1 border-b border-white/[0.05]">
                <span className="text-slate-500">FastAPI Backend:</span>
                <span className="text-emerald-400">ONLINE :8000</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-white/[0.05]">
                <span className="text-slate-500">Database:</span>
                <span className="text-cyan-400">SQLite/PostgreSQL</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-white/[0.05]">
                <span className="text-slate-500">ML Pipeline:</span>
                <span className="text-indigo-300">RoBERTa Transformer</span>
              </div>
              <div className="flex justify-between items-center py-1">
                <span className="text-slate-500">Chain Status:</span>
                <span className="text-amber-400">SEALED (SHA-256)</span>
              </div>
            </div>
          </div>
        </div>

        <div className="pt-6 border-t border-white/[0.06] flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-slate-500">
          <p>© 2026 ThreatLens Team Kiz915 • SIH 2026 Problem SIH26106</p>
          <div className="flex items-center gap-4 mt-2 sm:mt-0">
            <span className="hover:text-slate-400">SHA-256 Cryptographic Sealing</span>
            <span>•</span>
            <span className="hover:text-slate-400">Zero-Trust Header Extraction</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
