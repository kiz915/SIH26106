'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, useEffect } from 'react';
import {
  Shield,
  LayoutDashboard,
  Upload,
  FolderArchive,
  Blocks,
  Map,
  Activity,
  Menu,
  X,
  Sun,
  Moon,
  PlusCircle,
  Search,
} from 'lucide-react';
import { checkHealth } from '@/lib/api';
import { useTheme } from '@/context/ThemeContext';

const navItems = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/analyze', label: 'Analysis', icon: Upload },
  { href: '/cases', label: 'Cases', icon: FolderArchive },
  { href: '/blockchain', label: 'Ledger', icon: Blocks },
  { href: '/map', label: 'Map', icon: Map },
  { href: '/status', label: 'Status', icon: Activity },
];

export default function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [apiStatus, setApiStatus] = useState('checking');
  const [latency, setLatency] = useState(24);
  const { theme, toggleTheme } = useTheme();

  useEffect(() => {
    let active = true;
    const verifyNodes = async () => {
      const start = Date.now();
      try {
        const res = await checkHealth();
        if (active) {
          setLatency(Math.max(12, Date.now() - start));
          setApiStatus(res.status === 'online' ? 'online' : 'offline');
        }
      } catch {
        if (active) setApiStatus('offline');
      }
    };

    verifyNodes();
    const timer = setInterval(verifyNodes, 15000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const isDark = theme === 'dark';

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-[var(--border-subtle)] bg-[var(--glass-bg)] backdrop-blur-xl transition-colors duration-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-3">
          {/* Brand Logo (Surgical Crosshair / Shield) */}
          <Link href="/" className="flex items-center gap-2.5 shrink-0 group">
            <div className="w-8 h-8 rounded-lg bg-surface-container border border-[var(--border-subtle)] flex items-center justify-center transition-colors group-hover:border-[var(--primary-cyan)]">
              <Shield className="w-4 h-4 text-[var(--primary-cyan)]" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-bold tracking-tight text-[var(--text-primary)] leading-none">
                Threat<span className="text-[var(--primary-cyan)]">Lens</span>
              </span>
              <span className="text-[9px] tracking-wider text-[var(--text-muted)] uppercase leading-tight mt-0.5">
                Email Forensics
              </span>
            </div>
          </Link>

          {/* Desktop Navigation Links */}
          <div className="hidden lg:flex items-center gap-1 shrink-0">
            {navItems.map(({ href, label, icon: Icon }) => {
              const isActive = pathname === href || (href !== '/' && pathname.startsWith(href));
              return (
                <Link
                  key={href}
                  href={href}
                  className={`relative flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors ${
                    isActive
                      ? 'text-[var(--primary-cyan)] bg-[var(--primary-cyan)]/10 font-bold border border-[var(--border-cyan)]'
                      : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-container-high)] border border-transparent'
                  }`}
                >
                  <Icon
                    className={`w-3.5 h-3.5 shrink-0 ${
                      isActive ? 'text-[var(--primary-cyan)]' : 'text-[var(--text-muted)]'
                    }`}
                  />
                  <span>{label}</span>
                </Link>
              );
            })}
          </div>

          {/* Desktop Right Controls (Search, Ingest, Status, Theme) */}
          <div className="hidden lg:flex items-center gap-3 shrink-0">
            {/* Quick Ingest Button */}
            <Link
              href="/analyze"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold bg-[var(--primary-cyan)] text-[#05070b] hover:brightness-110 transition-all shadow-sm"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Analyze Email</span>
            </Link>

            {/* Live Backend Telemetry Pill */}
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md border border-[var(--border-subtle)] bg-[var(--surface-container-low)] text-xs font-mono whitespace-nowrap">
              <span
                className={`w-2 h-2 rounded-full ${
                  apiStatus === 'online'
                    ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]'
                    : 'bg-rose-500 shadow-[0_0_6px_#ef4444]'
                }`}
              />
              <span className="text-[11px] font-medium text-[var(--text-secondary)]">
                {apiStatus === 'online' ? `API :8000 (${latency}ms)` : 'OFFLINE'}
              </span>
            </div>

            {/* Theme Switcher */}
            <button
              onClick={toggleTheme}
              className="p-2 rounded-md border border-[var(--border-subtle)] bg-[var(--surface-container-low)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-cyan)] transition-all cursor-pointer"
              title={`Switch to ${isDark ? 'Clinical Light Mode' : 'Obsidian Dark Mode'}`}
              aria-label="Toggle Theme"
            >
              {isDark ? (
                <Sun className="w-4 h-4 text-amber-400" />
              ) : (
                <Moon className="w-4 h-4 text-indigo-500" />
              )}
            </button>
          </div>

          {/* Mobile Right Controls (< lg) */}
          <div className="flex items-center gap-2 lg:hidden">
            <div className="flex items-center gap-1 px-2 py-1 rounded border border-[var(--border-subtle)] bg-[var(--surface-container-low)] text-[10px] font-mono">
              <span
                className={`w-2 h-2 rounded-full ${
                  apiStatus === 'online' ? 'bg-emerald-500' : 'bg-rose-500'
                }`}
              />
              <span className="font-bold text-[var(--text-primary)]">
                {apiStatus === 'online' ? ':8000' : 'OFF'}
              </span>
            </div>
            <button
              onClick={toggleTheme}
              className="p-2 rounded border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] bg-[var(--surface-container-low)] cursor-pointer"
              aria-label="Toggle Theme"
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-indigo-500" />}
            </button>
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="p-2 rounded border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] bg-[var(--surface-container-low)] cursor-pointer"
              aria-label="Toggle Navigation Menu"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="lg:hidden border-t border-[var(--border-subtle)] bg-[var(--surface-base)] px-4 pt-3 pb-5 space-y-1">
          {navItems.map(({ href, label, icon: Icon }) => {
            const isActive = pathname === href || (href !== '/' && pathname.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                onClick={() => setMobileOpen(false)}
                className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'text-[var(--primary-cyan)] bg-[var(--primary-cyan)]/10 font-bold border border-[var(--border-cyan)]'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-container-high)]'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{label}</span>
              </Link>
            );
          })}
          <div className="pt-2">
            <Link
              href="/analyze"
              onClick={() => setMobileOpen(false)}
              className="flex items-center justify-center gap-2 w-full py-2.5 rounded-md text-xs font-bold bg-[var(--primary-cyan)] text-[#05070b]"
            >
              <PlusCircle className="w-4 h-4" />
              <span>Analyze Email</span>
            </Link>
          </div>
        </div>
      )}
    </nav>
  );
}
