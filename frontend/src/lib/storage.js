/**
 * LocalStorage helpers for analysis history
 */

const STORAGE_KEY = 'sih26106_history';
const MAX_HISTORY = 50;

export function getHistory() {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function saveAnalysis(result) {
  if (typeof window === 'undefined') return;
  try {
    const history = getHistory();
    const entry = {
      case_id: result.case_id,
      subject: result.email?.subject || 'No Subject',
      from: result.email?.from || result.email?.from_address || 'Unknown',
      risk_score: result.risk?.score,
      risk_classification: result.risk?.classification,
      timestamp: result.metadata?.analysis_timestamp,
      file_name: result.metadata?.file_name,
      data: result,
    };
    // Prepend and limit
    const updated = [entry, ...history.filter(h => h.case_id !== result.case_id)].slice(0, MAX_HISTORY);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // Ignore storage errors
  }
}

export function getAnalysis(caseId) {
  const history = getHistory();
  const entry = history.find(h => h.case_id === caseId);
  return entry?.data || null;
}

export function clearHistory() {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
}
