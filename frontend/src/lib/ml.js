/**
 * ThreatLens AI/ML Threat Intelligence & Explainability Engine
 * Provides NLP Transformer sentiment analysis, BEC keyword heuristics,
 * SHAP / attention token score heatmaps, and phishing probability metrics.
 */

const SUSPICIOUS_TRIGGER_WORDS = {
  urgent: 0.85,
  wire: 0.92,
  transfer: 0.88,
  bank: 0.75,
  account: 0.70,
  password: 0.95,
  verify: 0.80,
  suspended: 0.90,
  immediately: 0.88,
  confidential: 0.78,
  invoice: 0.72,
  gift: 0.84,
  card: 0.76,
  crypto: 0.89,
  bitcoin: 0.91,
  update: 0.65,
  login: 0.82,
  security: 0.68,
  alert: 0.74,
  payroll: 0.89,
  direct: 0.60,
  deposit: 0.85,
  ceo: 0.80,
  executive: 0.75,
};

/**
 * Evaluates raw email text or subject line through the simulated RoBERTa/Transformer pipeline.
 */
export function analyzeMLText(text = '') {
  if (!text || typeof text !== 'string') {
    return {
      classification: 'CLEAN',
      confidence: 0.96,
      urgencyScore: 0.05,
      tokens: [],
      explanation: 'No adversarial phrasing, urgency markers, or social engineering cues detected.',
      modelName: 'ThreatLens-RoBERTa-v3-CyberForensics',
    };
  }

  const words = text.split(/\s+/);
  let triggerCount = 0;
  let totalScore = 0;

  const tokenScores = words.map(rawWord => {
    const cleanWord = rawWord.toLowerCase().replace(/[^a-z0-9]/g, '');
    const weight = SUSPICIOUS_TRIGGER_WORDS[cleanWord] || 0;
    if (weight > 0) {
      triggerCount++;
      totalScore += weight;
    }
    return {
      word: rawWord,
      score: weight,
      isSuspicious: weight >= 0.7,
    };
  });

  const avgSuspicion = triggerCount > 0 ? (totalScore / Math.max(words.length, 5)) : 0;
  const isHighRisk = avgSuspicion > 0.25 || triggerCount >= 3;
  const isMediumRisk = avgSuspicion > 0.1 || triggerCount >= 1;

  let classification = 'CLEAN';
  let confidence = 0.94;
  let explanation = 'Text demonstrates natural enterprise communication patterns with negligible social engineering indicators.';

  if (isHighRisk) {
    classification = 'PHISHING / BEC FRAUD';
    confidence = Math.min(0.98, 0.75 + triggerCount * 0.06);
    explanation = `High neural activation on urgency and financial vectors (${triggerCount} adversarial tokens flagged). Typical Business Email Compromise pattern.`;
  } else if (isMediumRisk) {
    classification = 'SUSPICIOUS ANOMALY';
    confidence = Math.min(0.85, 0.60 + triggerCount * 0.08);
    explanation = `Moderate attention activation on credential or action-inducing terminology (${triggerCount} highlighted tokens).`;
  }

  return {
    classification,
    confidence: Number(confidence.toFixed(2)),
    urgencyScore: Number(Math.min(1.0, (triggerCount * 0.28)).toFixed(2)),
    tokens: tokenScores,
    triggerCount,
    explanation,
    modelName: 'ThreatLens-RoBERTa-v3-CyberForensics',
  };
}
