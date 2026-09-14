/**
 * ThreatLens - SIH26106 Backend API Client
 * Connects to FastAPI forensic server endpoints.
 * Includes mock-mode support for offline/demo use.
 */

import { API_BASE } from './constants';

const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK === 'true';

/**
 * Static mock analysis result matching the backend EmailAnalysisResponse schema.
 * Used when NEXT_PUBLIC_USE_MOCK=true so the frontend works without a running backend.
 */
const MOCK_ANALYSIS = {
  case_id: 'CASE-MOCK-BEC-001',
  email: {
    from: '"Executive Office" <ceo@legit-corp.example>',
    from_address: 'ceo@legit-corp.example',
    to: 'victim-analyst@target-corp.example',
    subject: 'URGENT: Immediate Action Required - Confidential Wire Transfer Invoice Overdue',
    date: '2026-09-06T15:31:50Z',
    message_id: '<20260906153150.998234@suspicious-relay.external-net.example>',
    return_path: 'bounce-handler@external-secure-portal.xyz',
    reply_to: 'finance-processing@external-secure-portal.xyz',
    body_preview: 'Dear Finance Team, URGENT NOTICE: Immediate action required. Our critical vendor account is at risk of account suspended status within 24 hours to verify. Please execute the confidential wire transfer for the overdue invoice immediately...',
  },
  headers: {
    from: '"Executive Office" <ceo@legit-corp.example>',
    to: 'victim-analyst@target-corp.example',
    subject: 'URGENT: Immediate Action Required - Confidential Wire Transfer Invoice Overdue',
    date: '2026-09-06T15:31:50Z',
    message_id: '<20260906153150.998234@suspicious-relay.external-net.example>',
    return_path: 'bounce-handler@external-secure-portal.xyz',
    reply_to: 'finance-processing@external-secure-portal.xyz',
  },
  authentication: {
    spf: { status: 'FAIL', detail: 'sender IP 198.51.100.42 is not authorized for domain legit-corp.example' },
    dkim: { status: 'FAIL', detail: 'bad signature for header.d=legit-corp.example' },
    dmarc: { status: 'FAIL', detail: 'p=reject dis=none, header.from=legit-corp.example' },
  },
  relay_path: [
    { hop_number: 1, ip: '203.0.113.88', ip_type: 'public', from_host: 'dynamic-pool.isp.example', by_host: 'suspicious-relay.external-net.example', delay_seconds: 0, lat: 28.6139, lng: 77.2090 },
    { hop_number: 2, ip: '198.51.100.42', ip_type: 'public', from_host: 'suspicious-relay.external-net.example', by_host: 'mail-gateway.target-corp.example', delay_seconds: 4, lat: 37.7749, lng: -122.4194 },
    { hop_number: 3, ip: '192.0.2.10', ip_type: 'public', from_host: 'mail-gateway.target-corp.example', by_host: 'mx1.internal.target-corp.example', delay_seconds: 5, lat: 39.0438, lng: -77.4874 },
  ],
  iocs: {
    urls: ['http://198.51.100.42/portal/login?id=9928'],
    domains: ['external-secure-portal.xyz', 'legit-corp.example'],
    ip_addresses: ['203.0.113.88', '198.51.100.42', '192.0.2.10'],
    email_addresses: ['ceo@legit-corp.example', 'bounce-handler@external-secure-portal.xyz', 'finance-processing@external-secure-portal.xyz'],
  },
  risk: {
    score: 92,
    classification: 'CRITICAL RISK',
    scoring_type: 'Deterministic Rule Pipeline + NLP Heuristic',
    signals: [
      { signal: 'SPF authentication failure', severity: 'HIGH', category: 'Authentication', weight: 25 },
      { signal: 'DKIM signature verification failed', severity: 'HIGH', category: 'Authentication', weight: 20 },
      { signal: 'DMARC policy enforcement failure', severity: 'HIGH', category: 'Authentication', weight: 20 },
      { signal: 'Reply-To domain mismatch from sender', severity: 'CRITICAL', category: 'Envelope Spoofing', weight: 15 },
      { signal: 'Return-Path envelope domain mismatch', severity: 'CRITICAL', category: 'Envelope Spoofing', weight: 12 },
      { signal: 'Urgency language detected in subject/body', severity: 'MEDIUM', category: 'Social Engineering', weight: 8 },
      { signal: 'Bare IP URL detected in email body', severity: 'HIGH', category: 'IOC', weight: 10 },
    ],
    ml_signals: {
      phishing_probability: 0.94,
      bec_probability: 0.88,
      model_name: 'ThreatLens-NLP-v2',
      confidence: 0.91,
    },
  },
  metadata: {
    case_id: 'CASE-MOCK-BEC-001',
    evidence_id: 'EVID-MOCK-001',
    analysis_timestamp: new Date().toISOString(),
    file_name: 'ceo_fraud_bec.eml',
    file_size_bytes: 3842,
    execution_time_ms: 127,
    parser_version: '2.4.0',
    evidence_hash: 'a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890',
  },
};

const MOCK_CASES = {
  cases: [
    {
      case_id: MOCK_ANALYSIS.case_id,
      original_filename: MOCK_ANALYSIS.metadata.file_name,
      risk_score: MOCK_ANALYSIS.risk.score,
      classification: MOCK_ANALYSIS.risk.classification,
      created_at: MOCK_ANALYSIS.metadata.analysis_timestamp,
      file_size: MOCK_ANALYSIS.metadata.file_size_bytes,
      status: 'ANALYZED',
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const MOCK_CASE_DETAIL = {
  case_id: MOCK_ANALYSIS.case_id,
  analysis: MOCK_ANALYSIS,
  evidence: {
    evidence_id: MOCK_ANALYSIS.metadata.evidence_id,
    case_id: MOCK_ANALYSIS.case_id,
    sha256: MOCK_ANALYSIS.metadata.evidence_hash,
    original_filename: MOCK_ANALYSIS.metadata.file_name,
    file_size: MOCK_ANALYSIS.metadata.file_size_bytes,
    collected_at: MOCK_ANALYSIS.metadata.analysis_timestamp,
    storage_reference: 'mock-storage',
  },
};

const MOCK_EVIDENCE = MOCK_CASE_DETAIL.evidence;

const MOCK_HEALTH = { status: 'online', service: 'SIH26106 Email Threat Detection API', version: '2.4.0', timestamp: new Date().toISOString() };

/**
 * Uploads and analyzes raw .eml file.
 * Returns structured EmailAnalysisResponse with case_id.
 */
export async function analyzeEmail(file) {
  if (USE_MOCK) {
    // Simulate network latency for realistic UX
    await new Promise((r) => setTimeout(r, 1200));
    return { ...MOCK_ANALYSIS, metadata: { ...MOCK_ANALYSIS.metadata, analysis_timestamp: new Date().toISOString() } };
  }

  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    let detail = 'Forensic analysis failed';
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {
      // ignore parse error
    }
    throw new Error(detail);
  }

  return res.json();
}

/**
 * Lists stored forensic cases from backend database.
 */
export async function listCases(limit = 50, offset = 0) {
  if (USE_MOCK) return MOCK_CASES;

  try {
    const res = await fetch(`${API_BASE}/cases?limit=${limit}&offset=${offset}`, {
      cache: 'no-store',
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch cases: HTTP ${res.status}`);
    }
    return res.json();
  } catch (err) {
    console.warn('Backend cases endpoint unavailable, falling back:', err.message);
    return null;
  }
}

/**
 * Gets full case details and analysis report from backend database.
 */
export async function getCaseDetail(caseId) {
  if (USE_MOCK) return MOCK_CASE_DETAIL;

  try {
    const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseId)}`, {
      cache: 'no-store',
    });
    if (!res.ok) {
      return null;
    }
    return res.json();
  } catch (err) {
    console.warn(`Backend case details unavailable for ${caseId}:`, err.message);
    return null;
  }
}

/**
 * Gets digital evidence record and SHA-256 digest for a case.
 */
export async function getCaseEvidence(caseId) {
  if (USE_MOCK) return MOCK_EVIDENCE;

  try {
    const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseId)}/evidence`, {
      cache: 'no-store',
    });
    if (!res.ok) {
      return null;
    }
    return res.json();
  } catch (err) {
    console.warn(`Backend case evidence unavailable for ${caseId}:`, err.message);
    return null;
  }
}

/**
 * Health check probe.
 */
export async function checkHealth() {
  if (USE_MOCK) return MOCK_HEALTH;

  try {
    const res = await fetch(`${API_BASE}/health`, { cache: 'no-store' });
    if (!res.ok) return { status: 'offline' };
    return res.json();
  } catch {
    return { status: 'offline' };
  }
}
