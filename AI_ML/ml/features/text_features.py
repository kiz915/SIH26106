"""Text-based feature extraction using lexical rules."""

import re
from typing import TypedDict

from ml.config import CONFIG


class TextFeatureFlags(TypedDict):
    urgency_detected: bool
    fear_detected: bool
    credential_request: bool
    financial_request: bool
    impersonation_detected: bool
    suspicious_cta: bool
    urgency_score: float
    fear_score: float
    credential_score: float
    financial_score: float
    impersonation_score: float
    overall_score: float


class TextFeatures:
    """Extract lexical features from email text for threat detection."""

    def __init__(self):
        cfg = CONFIG.get("features", {}).get("text", {})
        self.urgency_words = cfg.get("urgency_words", [
            "urgent", "immediately", "right now", "asap", "within 24 hours", "suspend", "expire"
        ])
        self.fear_words = cfg.get("fear_words", [
            "compromised", "unauthorized", "suspended", "blocked", "security breach"
        ])
        self.credential_keywords = cfg.get("credential_keywords", [
            "password", "login", "verify", "confirm identity", "credentials"
        ])
        self.financial_keywords = cfg.get("financial_keywords", [
            "wire transfer", "payment", "bank account", "invoice", "due today", "processing fee"
        ])
        self.impersonation_cues = cfg.get("impersonation_cues", [
            "dear employee", "dear customer", "ceo", "cfo", "security team"
        ])
        self.suspicious_ctas = cfg.get("suspicious_ctas", [
            "click here", "click below", "verify now", "confirm now"
        ])

    def extract(self, text: str, subject: str = "") -> TextFeatureFlags:
        """Extract features from combined subject+body text."""
        full_text = f"{subject} {text}".lower()
        
        urgency_hits = [w for w in self.urgency_words if w.lower() in full_text]
        fear_hits = [w for w in self.fear_words if w.lower() in full_text]
        credential_hits = [w for w in self.credential_keywords if w.lower() in full_text]
        financial_hits = [w for w in self.financial_keywords if w.lower() in full_text]
        impersonation_hits = [w for w in self.impersonation_cues if w.lower() in full_text]
        cta_hits = [w for w in self.suspicious_ctas if w.lower() in full_text]

        urgency_score = min(100.0, len(urgency_hits) * 25.0)
        fear_score = min(100.0, len(fear_hits) * 30.0)
        credential_score = min(100.0, len(credential_hits) * 35.0)
        financial_score = min(100.0, len(financial_hits) * 25.0)
        impersonation_score = min(100.0, len(impersonation_hits) * 30.0)

        raw_score = (
            urgency_score * 0.2 +
            fear_score * 0.25 +
            credential_score * 0.25 +
            financial_score * 0.15 +
            impersonation_score * 0.15
        )
        overall_score = min(100.0, raw_score)

        return TextFeatureFlags(
            urgency_detected=len(urgency_hits) > 0,
            fear_detected=len(fear_hits) > 0,
            credential_request=len(credential_hits) > 0,
            financial_request=len(financial_hits) > 0,
            impersonation_detected=len(impersonation_hits) > 0,
            suspicious_cta=len(cta_hits) > 0,
            urgency_score=urgency_score,
            fear_score=fear_score,
            credential_score=credential_score,
            financial_score=financial_score,
            impersonation_score=impersonation_score,
            overall_score=overall_score
        )

    def get_flagged_spans(self, text: str, subject: str = "", top_k: int = 5) -> list[dict]:
        """Return top-k flagged spans with character offsets."""
        spans = []
        full_text = f"{subject} {text}".lower()
        
        all_hits = []
        for word in self.urgency_words:
            for match in re.finditer(re.escape(word.lower()), full_text):
                all_hits.append((match.start(), match.end(), word, "urgency", 0.25))
        for word in self.fear_words:
            for match in re.finditer(re.escape(word.lower()), full_text):
                all_hits.append((match.start(), match.end(), word, "fear", 0.30))
        for word in self.credential_keywords:
            for match in re.finditer(re.escape(word.lower()), full_text):
                all_hits.append((match.start(), match.end(), word, "credential", 0.35))
        for word in self.financial_keywords:
            for match in re.finditer(re.escape(word.lower()), full_text):
                all_hits.append((match.start(), match.end(), word, "financial", 0.25))
        for word in self.impersonation_cues:
            for match in re.finditer(re.escape(word.lower()), full_text):
                all_hits.append((match.start(), match.end(), word, "impersonation", 0.30))
        for word in self.suspicious_ctas:
            for match in re.finditer(re.escape(word.lower()), full_text):
                all_hits.append((match.start(), match.end(), word, "suspicious_cta", 0.20))

        all_hits.sort(key=lambda x: x[4], reverse=True)
        for start, end, word, reason, weight in all_hits[:top_k]:
            spans.append({
                "text": word,
                "start": start,
                "end": end,
                "reason": reason,
                "weight": weight
            })
        return spans
