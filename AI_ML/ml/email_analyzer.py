"""Main EmailAnalyzer orchestrator - the stable public API."""

import logging
import time
from datetime import datetime, timezone
from typing import Any

from ml import config
from ml.classifier import Classifier
from ml.explainer import Explainer
from ml.features.header_features import HeaderFeatures
from ml.features.text_features import TextFeatures
from ml.features.url_features import UrlFeatures
from ml.preprocessing import preprocess_email
from ml.risk_scorer import get_fusion_strategy, score_to_risk_level
from ml.schemas import (
    AnalysisResult, Classification, FlaggedSpan, HeaderAnalysis,
    IOCs, ModelMetadata, Reason, TextAnalysis, TowerScores, UrlAnalysis
)

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """
    Main orchestrator for email threat analysis.
    
    Usage:
        analyzer = EmailAnalyzer()
        analyzer.warmup()
        result = analyzer.analyze_email(parsed_email_dict)
    """

    def __init__(self, config_path: str = "configs/ml.yaml"):
        self.config = config.load_config(config_path)
        self.classifier = Classifier()
        self.text_features = TextFeatures()
        self.url_features = UrlFeatures()
        self.header_features = HeaderFeatures()
        self.explainer = Explainer()
        self.fusion_strategy = get_fusion_strategy()
        self._warm = False

    def warmup(self) -> None:
        """Load models once at startup."""
        logger.info("Warming up EmailAnalyzer...")
        start = time.time()
        self.classifier.load()
        elapsed = (time.time() - start) * 1000
        logger.info(f"Warmup complete in {elapsed:.1f}ms")
        self._warm = True

    def analyze_email(self, parsed_email: dict) -> dict:
        """
        Analyze a single email and return AnalysisResult dict.
        
        Args:
            parsed_email: ParsedEmail dict from Backend
            
        Returns:
            AnalysisResult dict conforming to frozen contract
        """
        start_time = time.time()

        preprocessed = preprocess_email(parsed_email)

        text_score = self.classifier.get_text_score(preprocessed.body_text, preprocessed.subject)
        text_flags = self.text_features.extract(preprocessed.body_text, preprocessed.subject)

        # Get flagged spans - use Captum if configured and model available
        if (self.explainer.span_highlight_method == "captum" 
            and self.classifier.is_model_loaded()
            and self.classifier.model is not None
            and self.classifier.tokenizer is not None):
            flagged_spans = self.explainer.get_captum_spans(
                preprocessed.body_text,
                preprocessed.subject,
                model=self.classifier.model,
                tokenizer=self.classifier.tokenizer,
                top_k=self.explainer.max_flagged_spans
            )
            # Fallback to lexicon if Captum returns empty
            if not flagged_spans:
                flagged_spans = self.text_features.get_flagged_spans(
                    preprocessed.body_text, preprocessed.subject, top_k=5
                )
        else:
            flagged_spans = self.text_features.get_flagged_spans(
                preprocessed.body_text, preprocessed.subject, top_k=5
            )

        header_result = self.header_features.extract(parsed_email)
        header_score = header_result["score"]

        url_results = [self.url_features.analyze_url(url) for url in preprocessed.urls]
        url_score = self.url_features.aggregate_score(url_results)

        classification = self.classifier.classify(preprocessed.body_text, preprocessed.subject)

        fusion_features = {
            "auth_results": parsed_email.get("auth_results"),
            "urls": preprocessed.urls,
        }
        fusion_score = self.fusion_strategy.fuse(text_score, url_score, header_score, fusion_features)

        risk_level = score_to_risk_level(fusion_score)
        threat_category = self.explainer.derive_threat_category(
            classification["label"], text_flags, url_results
        )

        reasons = self.explainer.generate_reasons(
            text_flags, header_result, url_results, classification["label"]
        )

        all_iocs = IOCs(
            ips=list(set(preprocessed.ips + header_result.get("iocs", {}).get("ips", []))),
            domains=list(set(preprocessed.domains)),
            reply_to_addresses=preprocessed.reply_to_addresses,
            urls=preprocessed.urls
        )

        url_analysis = [
            UrlAnalysis(url=url, malicious_prob=r["malicious_prob"], flags=r["flags"])
            for url, r in zip(preprocessed.urls, url_results)
        ]

        latency_ms = (time.time() - start_time) * 1000

        result = AnalysisResult(
            schema_version="1.0",
            message_id=parsed_email.get("message_id", ""),
            fraud_score=round(fusion_score, 1),
            risk_level=risk_level,
            classification=Classification(
                label=classification["label"],
                confidence=round(classification["confidence"], 3),
                all_scores={k: round(v, 3) for k, v in classification["all_scores"].items()}
            ),
            threat_category=threat_category,
            tower_scores=TowerScores(
                text=round(text_score, 1),
                url=round(url_score, 1),
                header=round(header_score, 1)
            ),
            text_analysis=TextAnalysis(
                flagged_spans=[FlaggedSpan(**span) for span in flagged_spans],
                urgency_detected=text_flags["urgency_detected"],
                impersonation_detected=text_flags["impersonation_detected"],
                financial_request=text_flags["financial_request"],
                credential_request=text_flags["credential_request"]
            ),
            header_analysis=HeaderAnalysis(
                anomalies=[{**a} for a in header_result.get("anomalies", [])],
                auth_explanations=header_result.get("auth_explanations", {})
            ),
            url_analysis=url_analysis,
            iocs=all_iocs,
            reasons=[Reason(**r) for r in reasons],
            model_metadata=ModelMetadata(
                text_mode=self.classifier.mode,
                model_versions={},
                latency_ms=round(latency_ms, 2)
            ),
            generated_at=datetime.now(timezone.utc).isoformat()
        )

        return result.model_dump()

    def analyze_batch(self, emails: list[dict]) -> list[dict]:
        """Analyze multiple emails."""
        return [self.analyze_email(email) for email in emails]