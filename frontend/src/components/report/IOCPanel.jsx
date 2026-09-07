'use client';

import { useState } from 'react';
import { Globe, Link as LinkIcon, Server, Mail, Search, Copy, CheckCheck, ExternalLink } from 'lucide-react';

const tabs = [
  { key: 'urls', label: 'URLs', icon: LinkIcon },
  { key: 'domains', label: 'Domains', icon: Globe },
  { key: 'ips', label: 'IP Addresses', icon: Server },
  { key: 'emails', label: 'Email Addresses', icon: Mail },
];

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Ignore
    }
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded bg-[var(--surface-container)] hover:bg-[var(--surface-container-high)] text-[var(--text-muted)] hover:text-[var(--primary-cyan)] transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <CheckCheck className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

export default function IOCPanel({ iocs }) {
  const [activeTab, setActiveTab] = useState('urls');
  const [filterText, setFilterText] = useState('');

  if (!iocs) return null;

  const items = iocs[activeTab] || [];
  const filtered = items.filter(item =>
    item.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="glass-card p-5 h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-[var(--primary-cyan)]" />
            <h3 className="text-sm font-bold text-[var(--text-primary)]">
              Indicators & Artifacts
            </h3>
          </div>
          <span className="text-[11px] text-[var(--text-muted)]">
            Total: {Object.values(iocs).flat().length} items
          </span>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-3 p-1 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)]">
          {tabs.map(({ key, label, icon: Icon }) => {
            const count = (iocs[key] || []).length;
            const active = activeTab === key;
            return (
              <button
                key={key}
                onClick={() => {
                  setActiveTab(key);
                  setFilterText('');
                }}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-2 rounded-md text-xs transition-all cursor-pointer ${
                  active
                    ? 'bg-[var(--surface-base)] text-[var(--primary-cyan)] font-bold border border-[var(--border-cyan)] shadow-sm'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{label}</span>
                {count > 0 && (
                  <span
                    className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold ${
                      active ? 'bg-[var(--primary-cyan)]/15 text-[var(--primary-cyan)]' : 'bg-[var(--surface-container)] text-[var(--text-muted)]'
                    }`}
                  >
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Filter input */}
        {items.length > 5 && (
          <div className="relative mb-2">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)]" />
            <input
              type="text"
              value={filterText}
              onChange={e => setFilterText(e.target.value)}
              placeholder={`Filter ${activeTab}...`}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)] text-xs font-mono text-[var(--text-primary)] outline-none focus:border-[var(--primary-cyan)]"
            />
          </div>
        )}
      </div>

      {/* Content list */}
      <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
        {filtered.length === 0 ? (
          <p className="text-center py-6 text-xs text-[var(--text-muted)] font-mono">
            {items.length === 0 ? `No ${activeTab} extracted.` : 'No matching entries found.'}
          </p>
        ) : (
          filtered.map((item, i) => (
            <div
              key={i}
              className="group flex items-center justify-between px-3 py-2 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)] hover:border-[var(--border-cyan)] transition-colors font-mono text-xs"
            >
              <span className="break-all text-[11px] text-[var(--text-primary)] mr-2 select-all font-medium">
                {item}
              </span>
              <div className="flex items-center gap-1 shrink-0">
                <CopyButton text={item} />
                {activeTab === 'urls' && (
                  <a
                    href={`https://www.virustotal.com/gui/search/${encodeURIComponent(item)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="p-1 rounded bg-[var(--surface-container)] hover:bg-[var(--surface-container-high)] text-[var(--text-muted)] hover:text-[var(--primary-cyan)] transition-colors"
                    title="Inspect on VirusTotal"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
                {activeTab === 'ips' && (
                  <a
                    href={`https://ipinfo.io/${encodeURIComponent(item)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="p-1 rounded bg-[var(--surface-container)] hover:bg-[var(--surface-container-high)] text-[var(--text-muted)] hover:text-[var(--primary-cyan)] transition-colors"
                    title="Lookup IP Intelligence"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
