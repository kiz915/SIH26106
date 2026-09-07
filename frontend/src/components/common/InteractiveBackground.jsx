'use client';

import { useTheme } from '@/context/ThemeContext';

export default function InteractiveBackground() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <div className="fixed inset-0 pointer-events-none z-[-1] overflow-hidden">
      {/* Precision Forensic Grid (Stitch System) */}
      <div
        className="absolute inset-0 transition-opacity duration-500"
        style={{
          backgroundImage: isDark
            ? `linear-gradient(to right, rgba(255, 255, 255, 0.025) 1px, transparent 1px),
               linear-gradient(to bottom, rgba(255, 255, 255, 0.025) 1px, transparent 1px)`
            : `linear-gradient(to right, rgba(0, 104, 117, 0.04) 1px, transparent 1px),
               linear-gradient(to bottom, rgba(0, 104, 117, 0.04) 1px, transparent 1px)`,
          backgroundSize: '32px 32px',
        }}
      />

      {/* Subtle Top-Center Forensic Illumination Vignette */}
      <div
        className="absolute -top-32 left-1/2 -translate-x-1/2 w-[900px] h-[350px] rounded-full blur-[100px] pointer-events-none transition-all duration-700"
        style={{
          background: isDark
            ? 'radial-gradient(ellipse at center, rgba(0, 229, 255, 0.07) 0%, rgba(37, 99, 235, 0.03) 50%, transparent 70%)'
            : 'radial-gradient(ellipse at center, rgba(2, 132, 199, 0.06) 0%, rgba(29, 78, 216, 0.02) 50%, transparent 70%)',
        }}
      />
    </div>
  );
}
