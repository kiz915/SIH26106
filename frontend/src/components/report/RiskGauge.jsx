'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, AlertTriangle, ShieldAlert, Skull } from 'lucide-react';
import { RISK_TIERS } from '@/lib/constants';

const icons = {
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Skull,
};

export default function RiskGauge({ score = 0, classification = 'LOW RISK' }) {
  const [displayScore, setDisplayScore] = useState(0);
  const tier = RISK_TIERS[classification] || RISK_TIERS['LOW RISK'];
  const IconComponent = icons[tier.icon] || ShieldCheck;

  // Animate score number counting up
  useEffect(() => {
    let start = 0;
    const end = Math.min(Math.max(score, 0), 100);
    const duration = 1200;
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = (end - start) / steps;

    const timer = setInterval(() => {
      start += increment;
      if (start >= end) {
        setDisplayScore(end);
        clearInterval(timer);
      } else {
        setDisplayScore(Math.round(start));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [score]);

  // Circular gauge calculations
  const radius = 68;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center relative py-2">
      {/* SVG Neon Gauge Meter */}
      <div className="relative w-44 h-44 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
          {/* Background Track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="var(--surface-container-high)"
            strokeWidth="10"
            fill="transparent"
          />
          {/* Neon Value Arc */}
          <motion.circle
            cx="80"
            cy="80"
            r={radius}
            stroke={tier.color}
            strokeWidth="10"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.4, ease: [0.16, 1, 0.3, 1] }}
            strokeLinecap="round"
            fill="transparent"
            style={{
              filter: `drop-shadow(0 0 8px ${tier.color}60)`,
            }}
          />
        </svg>

        {/* Center Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.div
            initial={{ scale: 0.5, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="flex flex-col items-center"
          >
            <span
              className="text-4xl font-black font-mono tracking-tight"
              style={{ color: tier.color }}
            >
              {displayScore}
            </span>
            <span className="text-[10px] font-mono text-[var(--text-muted)] -mt-1 tracking-widest uppercase font-bold">
              SCORE / 100
            </span>
          </motion.div>
        </div>
      </div>

      {/* Risk Tier Badge */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="mt-3 flex items-center gap-1.5 px-3.5 py-1 rounded-full text-xs font-mono font-bold tracking-wider uppercase border shadow-sm"
        style={{
          background: tier.bg,
          color: tier.color,
          borderColor: tier.border,
        }}
      >
        <IconComponent className="w-3.5 h-3.5" />
        <span>{tier.label}</span>
      </motion.div>
    </div>
  );
}
