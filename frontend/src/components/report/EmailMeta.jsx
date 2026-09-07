'use client';

import { Mail, Calendar, User, AtSign, FileText, Send, Reply } from 'lucide-react';

export default function EmailMeta({ email }) {
  if (!email) return null;

  const rows = [
    { label: 'From', value: email.from_address || email.from, icon: User, highlight: true },
    { label: 'To', value: Array.isArray(email.to) ? email.to.join(', ') : email.to, icon: Send },
    { label: 'Subject', value: email.subject || '(No Subject)', icon: FileText, bold: true },
    { label: 'Date', value: email.date || 'N/A', icon: Calendar },
    { label: 'Reply-To', value: email.reply_to || 'None (Matches From)', icon: Reply },
    { label: 'Return-Path', value: email.return_path || 'None', icon: AtSign },
    { label: 'Message-ID', value: email.message_id || 'N/A', icon: Mail, mono: true },
    { label: 'Content-Type', value: email.content_type || 'N/A', icon: FileText, mono: true },
  ];

  return (
    <div className="glass-card p-5 h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Mail className="w-5 h-5 text-[var(--primary-cyan)]" />
          <h3 className="text-sm font-bold font-mono text-[var(--text-primary)]">
            Parsed RFC 822 Header Metadata
          </h3>
        </div>

        <div className="space-y-2.5">
          {rows.map(({ label, value, icon: Icon, highlight, bold, mono }, i) => (
            <div
              key={i}
              className="flex flex-col sm:flex-row sm:items-baseline gap-1 sm:gap-3 p-2.5 rounded-lg bg-[var(--surface-container-low)] border border-[var(--border-subtle)] text-xs font-mono"
            >
              <span className="w-24 text-[var(--text-muted)] shrink-0 flex items-center gap-1.5 font-bold">
                <Icon className="w-3.5 h-3.5 text-[var(--primary-cyan)]" />
                {label}:
              </span>
              <span
                className={`break-all ${
                  highlight
                    ? 'text-[var(--primary-cyan)] font-bold'
                    : bold
                    ? 'text-[var(--text-primary)] font-sans text-sm font-bold'
                    : mono
                    ? 'text-[var(--text-secondary)] text-[11px]'
                    : 'text-[var(--text-primary)]'
                }`}
              >
                {value || 'None'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
