"""Tests for EmailAnalyzer orchestrator."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.email_analyzer import EmailAnalyzer


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(i: int) -> dict:
    fixture_files = list(FIXTURES_DIR.glob(f"fixture_{i:02d}_*.json"))
    if not fixture_files:
        pytest.skip(f"Fixture {i} not found")
    with open(fixture_files[0]) as f:
        return json.load(f)


class TestEmailAnalyzer:
    def setup_method(self):
        self.analyzer = EmailAnalyzer()
        self.analyzer.warmup()

    def test_analyze_legit_email_low_score(self):
        email = load_fixture(1)
        result = self.analyzer.analyze_email(email)
        assert result["fraud_score"] < 30
        assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_analyze_legit_urgent_invoice_stays_low(self):
        email = load_fixture(2)
        result = self.analyzer.analyze_email(email)
        assert result["fraud_score"] < 30

    def test_analyze_phishing_high_score(self):
        email = load_fixture(3)
        result = self.analyzer.analyze_email(email)
        assert result["fraud_score"] > 50

    def test_analyze_edge_case_empty(self):
        email = load_fixture(10)
        result = self.analyzer.analyze_email(email)
        assert "fraud_score" in result
        assert "risk_level" in result
        assert "classification" in result

    def test_all_required_fields_present(self):
        email = load_fixture(3)
        result = self.analyzer.analyze_email(email)
        required_fields = [
            "schema_version", "message_id", "fraud_score", "risk_level",
            "classification", "threat_category", "tower_scores",
            "text_analysis", "header_analysis", "url_analysis",
            "iocs", "reasons", "model_metadata", "generated_at"
        ]
        for field in required_fields:
            assert field in result, f"Missing field: {field}"

    def test_tower_scores_in_range(self):
        email = load_fixture(3)
        result = self.analyzer.analyze_email(email)
        for tower in ["text", "url", "header"]:
            assert 0 <= result["tower_scores"][tower] <= 100

    def test_flagged_spans_are_substrings(self):
        email = load_fixture(3)
        result = self.analyzer.analyze_email(email)
        body_text = email.get("body_text", "")
        for span in result["text_analysis"]["flagged_spans"]:
            assert span["text"].lower() in body_text.lower()

    def test_batch_analyze(self):
        emails = [load_fixture(i) for i in [1, 3, 10]]
        results = self.analyzer.analyze_batch(emails)
        assert len(results) == 3
        for result in results:
            assert "fraud_score" in result

    def test_canonical_json_deterministic(self):
        email = load_fixture(1)
        result1 = self.analyzer.analyze_email(email)
        result2 = self.analyzer.analyze_email(email)

        from ml.schemas import AnalysisResult
        r1 = AnalysisResult(**result1)
        r2 = AnalysisResult(**result2)
        assert r1.to_canonical_json() == r2.to_canonical_json()

    def test_latency_reasonable(self):
        email = load_fixture(1)
        result = self.analyzer.analyze_email(email)
        assert result["model_metadata"]["latency_ms"] < 5000

    def test_iocs_extracted(self):
        email = load_fixture(3)
        result = self.analyzer.analyze_email(email)
        assert "iocs" in result
        assert "urls" in result["iocs"]
