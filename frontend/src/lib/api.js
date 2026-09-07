/**
 * ThreatLens - SIH26106 Backend API Client
 * Connects to FastAPI forensic server endpoints.
 */

import { API_BASE } from './constants';

/**
 * Uploads and analyzes raw .eml file.
 * Returns structured EmailAnalysisResponse with case_id.
 */
export async function analyzeEmail(file) {
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
  try {
    const res = await fetch(`${API_BASE}/health`, { cache: 'no-store' });
    if (!res.ok) return { status: 'offline' };
    return res.json();
  } catch {
    return { status: 'offline' };
  }
}
