from dataclasses import dataclass
from typing import Dict, Any

from config.config import RiskLevel, ThreatLabel, RISK_THRESHOLDS, FP_CAP_CONFIDENCE, FP_CAP_MAX_SCORE
from src.nlp.classifier import NLPResult
from src.scoring.fusion import FusionStrategy, get_fusion_strategy

@dataclass
class ScoringResult:
    risk_score: int
    risk_level: RiskLevel
    classification: ThreatLabel
    threat_category: str
    confidence: float
    component_scores: Dict[str, float]
    fp_capped: bool

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value if hasattr(self.risk_level, 'value') else self.risk_level,
            "classification": self.classification.value if hasattr(self.classification, 'value') else self.classification,
            "threat_category": self.threat_category,
            "confidence": self.confidence,
            "component_scores": self.component_scores,
            "fp_capped": self.fp_capped
        }

class RiskScorer:
    def __init__(self, fusion_strategy: FusionStrategy = None):
        self.fusion = fusion_strategy if fusion_strategy is not None else get_fusion_strategy()

    def score(self, nlp_result: NLPResult, text_features: Any, url_features: Any, header_features: Any) -> ScoringResult:
        # 1. Build component scores
        if nlp_result.label == ThreatLabel.LEGITIMATE:
            nlp_threat_score = (1.0 - nlp_result.confidence) * 100
        else:
            nlp_threat_score = nlp_result.confidence * 100
            
        nlp_component = 0.5 * nlp_threat_score + 0.5 * text_features.score
        url_component = url_features.score
        header_component = header_features.score
        
        component_scores = {
            'nlp': nlp_component,
            'url': url_component,
            'header': header_component
        }

        # 2. Fuse
        raw_score = self.fusion.fuse(component_scores)
        
        # 3. FALSE-POSITIVE CAP
        fp_capped = False
        if (nlp_result.label == ThreatLabel.LEGITIMATE and 
            nlp_result.confidence > FP_CAP_CONFIDENCE and 
            url_features.score < 30 and 
            header_features.score < 30):
            raw_score = min(raw_score, FP_CAP_MAX_SCORE)
            fp_capped = True
            
        final_risk_score = int(round(raw_score))
        
        # 4. Determine risk_level from RISK_THRESHOLDS
        # Assume RISK_THRESHOLDS is a dict ordered from high to low or low to high.
        # We will match the highest threshold the score exceeds.
        risk_level = RiskLevel.LOW
        for level, threshold in sorted(RISK_THRESHOLDS.items(), key=lambda item: item[1], reverse=True):
            if final_risk_score >= threshold:
                risk_level = level
                break
                
        # 5. Classification
        classification = nlp_result.label
        
        # 6. Derive threat_category
        flags = url_features.flags if hasattr(url_features, 'flags') else {}
        
        if classification == ThreatLabel.PHISHING:
            if getattr(text_features, 'credential_request', 0.0) > 0.3 or flags.get('login_keywords', False):
                threat_category = 'Credential Phishing'
            elif getattr(text_features, 'financial_request', 0.0) > 0.3:
                threat_category = 'Financial Phishing'
            else:
                threat_category = 'Generic Phishing'
        elif classification == ThreatLabel.BEC:
            threat_category = 'Business Email Compromise'
        elif classification == ThreatLabel.MALWARE:
            threat_category = 'Malware Delivery'
        elif classification == ThreatLabel.SCAM:
            if getattr(text_features, 'financial_request', 0.0) > 0.3:
                threat_category = 'Financial Scam'
            else:
                threat_category = 'Generic Scam'
        elif classification == ThreatLabel.IMPERSONATION:
            threat_category = 'Identity Impersonation'
        elif classification == ThreatLabel.SPAM:
            threat_category = 'Spam / Unsolicited'
        elif classification == ThreatLabel.LEGITIMATE:
            threat_category = 'Legitimate'
        else:
            threat_category = 'Unknown'
            
        # 7. Confidence
        confidence = nlp_result.confidence
        if fp_capped:
            confidence = max(0.0, confidence - 0.1)
            
        return ScoringResult(
            risk_score=final_risk_score,
            risk_level=risk_level,
            classification=classification,
            threat_category=threat_category,
            confidence=confidence,
            component_scores=component_scores,
            fp_capped=fp_capped
        )
