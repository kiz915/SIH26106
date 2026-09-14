'use client';

import { Toaster } from 'react-hot-toast';

/**
 * Global toast notification provider.
 * Renders the react-hot-toast <Toaster /> component with cyberpunk styling
 * to match the ThreatLens Obsidian design system.
 */
export default function ToastProvider() {
  return (
    <Toaster
      position="top-right"
      toastOptions={{
        duration: 4000,
        style: {
          background: 'var(--surface-container, #1a1d23)',
          color: 'var(--text-primary, #e4e8ec)',
          border: '1px solid var(--border-subtle, #2a2d35)',
          fontSize: '13px',
          fontFamily: 'var(--font-jetbrains-mono), monospace',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)',
        },
        success: {
          iconTheme: {
            primary: '#00e5ff',
            secondary: '#0a0c10',
          },
        },
        error: {
          iconTheme: {
            primary: '#ff4b2b',
            secondary: '#0a0c10',
          },
        },
      }}
    />
  );
}
