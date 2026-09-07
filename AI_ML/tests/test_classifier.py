"""Tests for text classifier."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.classifier import Classifier


class TestClassifier:
    def setup_method(self):
        self.classifier = Classifier()

    def test_classify_rules_mode(self):
        self.classifier.mode = "rules_only"
        result = self.classifier.classify("URGENT: Verify your password now", "Test")
        assert "label" in result
        assert "confidence" in result
        assert "all_scores" in result
        assert result["label"] in ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "IMPERSONATION",
                                     "BEC_PAYMENT_DIVERSION", "CREDENTIAL_HARVESTING", "MALWARE_DELIVERY"]

    def test_classify_returns_valid_scores(self):
        self.classifier.mode = "rules_only"
        result = self.classifier.classify("Hello, this is a normal email", "Hi")
        for score in result["all_scores"].values():
            assert 0 <= score <= 100

    def test_get_text_score(self):
        score = self.classifier.get_text_score("URGENT: Account suspended", "Warning")
        assert 0 <= score <= 100

    def test_empty_text(self):
        self.classifier.mode = "rules_only"
        result = self.classifier.classify("", "")
        assert result["label"] in result["all_scores"]

    def test_rules_only_fallback(self):
        self.classifier.mode = "rules_only"
        result = self.classifier.classify("Click here to verify your account", "Verify")
        assert "credential" in str(result["all_scores"]).lower() or "suspicious" in str(result["all_scores"]).lower() or "phishing" in str(result["all_scores"]).lower()
