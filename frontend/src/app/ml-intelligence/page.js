'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  BrainCircuit,
  Cpu,
  Zap,
  Play,
  Copy,
  Layers,
  Activity,
  CheckCircle2,
  FileText,
  Sliders,
  SlidersHorizontal,
  Settings,
  ShieldAlert,
  Server
} from 'lucide-react';
import { listCases, getCaseDetail } from '@/lib/api';
import { getHistory } from '@/lib/storage';


export default function MLIntelligencePage() {
  const [inputText, setInputText] = useState(
    'URGENT: Executive Wire Transfer Authorization Required immediately for supplier invoice. Do not disclose this confidential transaction to finance.'
  );
  
  const [result, setResult] = useState({
    classification: 'CLEAN',
    riskScore: 0,
    matchedUrgency: [],
    matchedFinancial: [],
    totalMatches: 0,
    tokens: [],
    summary: 'Ready for analysis.'
  });
  
  const [cases, setCases] = useState([]);
  const [loadingCases, setLoadingCases] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Stitch Settings Configuration State
  const [sensitivity, setSensitivity] = useState(75);
  const [memoryDepth, setMemoryDepth] = useState(30);
  const [deepInspection, setDeepInspection] = useState(true);
  const [zeroDayDetection, setZeroDayDetection] = useState(true);

  useEffect(() => {
    async function fetchCases() {
      setLoadingCases(true);
      try {
        const res = await listCases(10, 0);
        if (res && res.cases && res.cases.length > 0) {
          setCases(res.cases);
        } else {
          setCases(getHistory());
        }
      } catch {
        setCases(getHistory());
      } finally {
        setLoadingCases(false);
      }
    }
    fetchCases();
  }, []);

  const handleRunInference = async () => {
    if (!inputText.trim()) return;
    setIsAnalyzing(true);
    
    try {
      const emailContent = `From: tester@local.com\nTo: threat-intel@local.com\nSubject: Inference Test\nDate: Sun, 6 Sep 2026 15:00:00 +0000\n\n${inputText}`;
      const blob = new Blob([emailContent], { type: 'message/rfc822' });
      const file = new File([blob], 'threat_test.eml', { type: 'message/rfc822' });
      
      const res = await analyzeEmail(file);
      
      const riskScore = res?.risk?.score || 0;
      const classification = res?.risk?.classification || 'CLEAN';
      const summary = res?.risk?.reasons?.join(' ') || 'Backend analyzed successfully.';
      
      // We map the backend signals back to the UI view
      const urgencySignals = res?.risk?.signals?.filter(s => s.name.includes('URGENCY')) || [];
      const financialSignals = res?.risk?.signals?.filter(s => s.name.includes('FINANCIAL') || s.name.includes('BEC')) || [];
      
      setResult({
        classification,
        riskScore,
        matchedUrgency: urgencySignals.map(s => s.description),
        matchedFinancial: financialSignals.map(s => s.description),
        totalMatches: (res?.risk?.signals?.length) || 0,
        tokens: [], // Not returned by baseline backend yet
        summary
      });
    } catch (e) {
      console.error("Inference Error:", e);
      setResult({
        classification: 'ERROR',
        riskScore: 0,
        matchedUrgency: [],
        matchedFinancial: [],
        totalMatches: 0,
        tokens: [],
        summary: `Analysis failed: ${e.message}`
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSelectCase = async (caseId) => {
    try {
      const detail = await getCaseDetail(caseId);
      const rep = detail?.analysis || detail?.analysis_report;
      if (rep) {
        const body =
          rep.email?.body_plain ||
          rep.headers?.subject ||
          '';
        if (body) {
          setInputText(body);
        }
      }
    } catch {
      // fallback
    }
  };

  const handleLoadPreset = (type) => {
    let text = '';
    if (type === 'bec') {
      text =
        'URGENT: Executive wire transfer of $84,500 needed immediately for confidential acquisition. Do not contact finance, transfer funds to beneficiary account today.';
    } else if (type === 'phish') {
      text =
        'Your Microsoft 365 password has expired! Verify your account immediately at http://corporate-it-auth-portal.com to prevent permanent suspension.';
    } else {
      text =
        'Hi Team, please find attached the meeting minutes and sprint goals for next week. Let me know if you have any questions.';
    }
    setInputText(text);
  };

  const isHighRisk = result.riskScore >= 60;
  const isSuspicious = result.riskScore >= 35 && result.riskScore < 60;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-16 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-6 border-b border-[var(--border-subtle)] gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-semibold text-[var(--primary-cyan)] uppercase tracking-wider">
              Threat Intelligence & Rule Engine
            </span>
            <span className="mono text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface-container-high)] text-[var(--text-muted)] border border-[var(--border-subtle)]">
              v4.2
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--text-primary)]">
            Intelligence Engine & Detection Rules
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Evaluate linguistic urgency markers, financial vectors, and configure heuristic sensitivity.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleLoadPreset('bec')}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500 transition-all cursor-pointer"
          >
            Load BEC Sample
          </button>
          <button
            onClick={() => handleLoadPreset('phish')}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500 transition-all cursor-pointer"
          >
            Load Phishing Sample
          </button>
          <button
            onClick={() => handleLoadPreset('clean')}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 transition-all cursor-pointer"
          >
            Load Clean Sample
          </button>
        </div>
      </div>

      {/* Bento Grid: Engine Status (4 cols) + Decision Visualizer (8 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Engine Status Panel (Span 4) */}
        <div className="lg:col-span-4 glass-panel p-6 rounded-lg border border-[var(--border-subtle)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-[var(--border-subtle)]">
              <span className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                Engine Status
              </span>
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span>ONLINE</span>
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex justify-between py-1.5 border-b border-[var(--border-subtle)]">
                <span className="text-[var(--text-muted)]">Rule Engine</span>
                <span className="font-medium text-[var(--text-primary)]">Heuristic Pipeline v4.2</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[var(--border-subtle)]">
                <span className="text-[var(--text-muted)]">Active Model</span>
                <span className="font-medium mono text-indigo-400">RoBERTa-Forensic</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[var(--border-subtle)]">
                <span className="text-[var(--text-muted)]">Analysis Mode</span>
                <span className="font-medium text-[var(--primary-cyan)]">Synchronous / Deterministic</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-[var(--text-muted)]">Indexed Cases</span>
                <span className="font-medium mono text-[var(--text-primary)]">{cases.length} Records</span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-3 border-t border-[var(--border-subtle)] text-[11px] text-[var(--text-muted)]">
            Connected to FastAPI backend (<span className="mono">127.0.0.1:8000</span>)
          </div>
        </div>

        {/* Heuristic Decision Tree & Token Heatmap (Span 8) */}
        <div className="lg:col-span-8 glass-panel p-6 rounded-lg border border-[var(--border-subtle)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-[var(--border-subtle)]">
              <span className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                Detection Breakdown
              </span>
              <span
                className={`text-xs font-semibold px-2.5 py-0.5 rounded ${
                  isHighRisk
                    ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                    : isSuspicious
                    ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                    : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                }`}
              >
                {result.classification} ({result.riskScore}/100)
              </span>
            </div>

            <div className="p-3.5 rounded bg-[var(--surface-container-low)] border border-[var(--border-subtle)] text-xs text-[var(--text-secondary)] mb-4">
              <span className="text-[var(--primary-cyan)] font-semibold block mb-1">
                Rule Rationale:
              </span>
              <p className="leading-relaxed text-[12px]">{result.summary}</p>
            </div>

            <div>
              <span className="text-[11px] font-semibold text-[var(--text-muted)] block mb-2 uppercase tracking-wider">
                Token Activation Heatmap:
              </span>
              <div className="p-3 rounded bg-[var(--surface-container-low)] border border-[var(--border-subtle)] flex flex-wrap gap-1.5 mono text-xs leading-relaxed max-h-32 overflow-y-auto">
                {result.tokens.map((tok, idx) => (
                  <span
                    key={idx}
                    className={`px-2 py-0.5 rounded transition-colors ${
                      tok.type === 'financial'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-semibold'
                        : tok.type === 'urgency'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40 font-semibold'
                        : 'text-[var(--text-primary)] hover:bg-[var(--surface-container-high)]'
                    }`}
                  >
                    {tok.word}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between text-xs text-[var(--text-muted)]">
            <span>Matches: {result.totalMatches} flag(s) active</span>
            <span className="text-rose-400 font-semibold">Urgency: {result.matchedUrgency.length} | BEC: {result.matchedFinancial.length}</span>
          </div>
        </div>
      </div>

      {/* Analysis Configuration Parameters */}
      <div className="glass-panel p-6 rounded-lg border border-[var(--border-subtle)]">
        <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-6 pb-2 border-b border-[var(--border-subtle)]">
          Detection Sensitivity Settings
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 text-xs">
          {/* Slider 1 */}
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-[var(--text-primary)] font-medium">Anomaly Sensitivity</span>
              <span className="text-[var(--primary-cyan)] font-bold mono">{sensitivity}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={sensitivity}
              onChange={(e) => setSensitivity(Number(e.target.value))}
              className="w-full appearance-none bg-[var(--surface-container-high)] h-1.5 rounded-full cursor-pointer accent-[var(--primary-cyan)]"
            />
            <p className="text-[11px] text-[var(--text-muted)] leading-tight">
              Higher values flag subtle phrasing anomalies.
            </p>
          </div>

          {/* Slider 2 */}
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-[var(--text-primary)] font-medium">Baseline Lookback</span>
              <span className="text-[var(--primary-cyan)] font-bold mono">{memoryDepth} Days</span>
            </div>
            <input
              type="range"
              min="1"
              max="90"
              value={memoryDepth}
              onChange={(e) => setMemoryDepth(Number(e.target.value))}
              className="w-full appearance-none bg-[var(--surface-container-high)] h-1.5 rounded-full cursor-pointer accent-[var(--primary-cyan)]"
            />
            <p className="text-[11px] text-[var(--text-muted)] leading-tight">
              Historical baseline window for comparison.
            </p>
          </div>

          {/* Toggle 1 */}
          <div className="flex items-center justify-between p-3 rounded bg-[var(--surface-container-low)] border border-[var(--border-subtle)]">
            <div>
              <span className="font-medium text-[var(--text-primary)] block">Deep Header Inspection</span>
              <span className="text-[10px] text-[var(--text-muted)]">Full RFC envelope parsing</span>
            </div>
            <button
              onClick={() => setDeepInspection(!deepInspection)}
              className={`w-9 h-5 rounded-full transition-colors relative cursor-pointer ${
                deepInspection ? 'bg-[var(--primary-cyan)]' : 'bg-[var(--surface-container-highest)]'
              }`}
            >
              <span
                className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                  deepInspection ? 'left-4.5' : 'left-0.5'
                }`}
              />
            </button>
          </div>

          {/* Toggle 2 */}
          <div className="flex items-center justify-between p-3 rounded bg-[var(--surface-container-low)] border border-[var(--border-subtle)]">
            <div>
              <span className="font-medium text-[var(--text-primary)] block">Typosquatting Check</span>
              <span className="text-[10px] text-[var(--text-muted)]">Detect lookalike domains</span>
            </div>
            <button
              onClick={() => setZeroDayDetection(!zeroDayDetection)}
              className={`w-9 h-5 rounded-full transition-colors relative cursor-pointer ${
                zeroDayDetection ? 'bg-[var(--primary-cyan)]' : 'bg-[var(--surface-container-highest)]'
              }`}
            >
              <span
                className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                  zeroDayDetection ? 'left-4.5' : 'left-0.5'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Interactive Text Input & Live Evaluation */}
      <div className="glass-panel p-6 rounded-lg border border-[var(--border-subtle)]">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-[var(--border-subtle)]">
          <span className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
            Threat Text Tester
          </span>
          <span className="mono text-xs text-[var(--text-muted)]">
            {inputText.length} characters
          </span>
        </div>

        <textarea
          rows={5}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste email text to evaluate against real-world BEC triggers..."
          className="w-full p-4 rounded bg-[var(--surface-floor)] border border-[var(--border-subtle)] mono text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--primary-cyan)] leading-relaxed"
        />

        <div className="mt-4 flex justify-end">
          <button
            onClick={handleRunInference}
            className="btn-cyber-primary px-5 py-2.5 rounded-xl text-xs font-semibold shadow-md"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Evaluate Text</span>
          </button>
        </div>
      </div>
    </div>
  );
}
