import sys
import os
import json
import hashlib
from typing import Dict, Any

from config.config import ThreatLabel, TextModelMode, RiskLevel, MODEL_VERSION, TEXT_MODEL_MODE, DEVICE
from src.features.text_features import extract_text_features
from src.features.url_features import extract_url_features
from src.features.header_features import extract_header_features
from src.nlp.classifier import NLPClassifier
from src.scoring.fusion import get_fusion_strategy
from src.scoring.risk_scorer import RiskScorer
from src.explainability.explainer import Explainer
from src.utils.preprocessing import clean_text, extract_urls_from_text, assemble_email_text


class EmailAnalyzer:
    """
    Main orchestration class for the email threat analysis pipeline.
    Coordinates feature extraction, NLP classification, risk scoring, and explainability.
    """

    def __init__(self, model_mode: TextModelMode = None, fusion_strategy: str = None):
        """
        Initialize the analyzer with the given configuration.
        """
        mode = model_mode if model_mode is not None else TEXT_MODEL_MODE
        self.classifier = NLPClassifier(mode=mode)
        self.scorer = RiskScorer(fusion_strategy=get_fusion_strategy(fusion_strategy))
        self.explainer = Explainer()
        self.model_metadata = {
            'name': self.classifier.model_name,
            'version': MODEL_VERSION,
            'mode': self.classifier._active_mode.value
        }

    def analyze_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the full analysis pipeline on the given email data.
        """
        # 1. Extract fields
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        sender = email_data.get('sender', '')
        # recipient = email_data.get('recipient', '') # Extracted but not used in features currently
        urls = email_data.get('urls', [])
        # attachments = email_data.get('attachments', []) # Available but not directly processed in MVP
        headers = email_data.get('headers', {})
        authentication = email_data.get('authentication', {})

        # 2. Preprocess
        raw_text = assemble_email_text(subject, body)
        text = clean_text(raw_text)
        
        if not urls:
            urls = extract_urls_from_text(body)

        # 3. Run features
        text_feat = extract_text_features(text)
        url_feat = extract_url_features(urls, body)
        header_feat = extract_header_features(headers, sender, authentication)

        # 4. Run NLP
        nlp_result = self.classifier.classify(text)

        # 5. Run scoring
        scoring_result = self.scorer.score(nlp_result, text_feat, url_feat, header_feat)

        # 6. Run explainability
        explanation = self.explainer.explain(
            nlp_result, text_feat, url_feat, header_feat, scoring_result, email_data
        )

        # 7. Build result dict
        result = {
            'risk_score': scoring_result.risk_score,
            'classification': scoring_result.classification.value,
            'confidence': round(scoring_result.confidence, 4),
            'risk_level': scoring_result.risk_level.value,
            'threat_category': scoring_result.threat_category,
            'reasons': explanation.reasons,
            'text_analysis': explanation.text_analysis,
            'url_analysis': explanation.url_analysis,
            'header_analysis': explanation.header_analysis,
            'iocs': explanation.iocs,
            'component_scores': scoring_result.component_scores,
            'fp_capped': scoring_result.fp_capped,
            'model': self.model_metadata
        }

        # 8. Add canonical hash
        result['hash_payload'] = self.canonical_hash(result)

        return result

    @staticmethod
    def _sort_recursive(obj: Any) -> Any:
        """Helper to recursively sort lists and dicts for deterministic hashing."""
        if isinstance(obj, dict):
            return {k: EmailAnalyzer._sort_recursive(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            # Try to sort the list if elements are sortable
            try:
                sorted_list = sorted(obj)
                return [EmailAnalyzer._sort_recursive(v) for v in sorted_list]
            except TypeError:
                return [EmailAnalyzer._sort_recursive(v) for v in obj]
        else:
            return obj

    @staticmethod
    def canonical_hash(result: Dict[str, Any]) -> str:
        """
        Generate a deterministic SHA-256 hash of the result payload.
        Excludes temporal and hash fields.
        """
        # Exclude certain fields
        excludes = {'hash_payload', 'timestamp', 'analysis_timestamp'}
        filtered_result = {k: v for k, v in result.items() if k not in excludes}
        
        sorted_result = EmailAnalyzer._sort_recursive(filtered_result)
        
        canonical_json = json.dumps(
            sorted_result,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True
        )
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def analyze_email(email_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    """
    Convenience wrapper to instantiate EmailAnalyzer and run analysis.
    Stable API contract for backend integration.
    """
    analyzer = EmailAnalyzer(**kwargs)
    return analyzer.analyze_email(email_data)
