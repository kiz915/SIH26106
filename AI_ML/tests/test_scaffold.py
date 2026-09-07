import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.schemas import ParsedEmail, AnalysisResult, LABELS, Classification, TextAnalysis, HeaderAnalysis, IOCs, ModelMetadata, TowerScores
from ml.config import DEVICE, CONFIG


class TestContracts:
    def test_labels_frozen(self):
        assert LABELS == [
            "LEGITIMATE",
            "SUSPICIOUS",
            "PHISHING",
            "IMPERSONATION",
            "BEC_PAYMENT_DIVERSION",
            "CREDENTIAL_HARVESTING",
            "MALWARE_DELIVERY",
        ]

    def test_parsed_email_empty(self):
        email = ParsedEmail()
        assert email.message_id == ""
        assert email.to == []

    def test_parsed_email_from_dict(self):
        data = {
            "message_id": "<test@example.com>",
            "from_address": "test@example.com",
            "from_display_name": "Test User",
            "reply_to": None,
            "to": ["recipient@example.com"],
            "subject": "Test Subject",
            "body_text": "Test body",
            "body_html": None,
            "received_chain": [],
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "headers_raw": {},
            "urls_in_body": [],
            "attachments": []
        }
        email = ParsedEmail(**data)
        assert email.message_id == "<test@example.com>"
        assert email.auth_results.spf == "pass"

    def test_analysis_result_structure(self):
        result = AnalysisResult(
            message_id="<test@example.com>",
            fraud_score=25.0,
            risk_level="MEDIUM",
            classification=Classification(label="SUSPICIOUS", confidence=0.7, all_scores={"SUSPICIOUS": 0.7}),
            threat_category="SUSPICIOUS",
            tower_scores=TowerScores(text=30.0, url=20.0, header=25.0),
            text_analysis=TextAnalysis(),
            header_analysis=HeaderAnalysis(),
            iocs=IOCs(),
            reasons=[],
            model_metadata=ModelMetadata(text_mode="rules_only", model_versions={}, latency_ms=5.0),
            generated_at="2026-09-06T00:00:00Z"
        )
        assert result.fraud_score == 25.0
        assert result.risk_level == "MEDIUM"

    def test_canonical_json_deterministic(self):
        result = AnalysisResult(
            message_id="<test@example.com>",
            fraud_score=25.0,
            risk_level="MEDIUM",
            classification=Classification(label="SUSPICIOUS", confidence=0.7, all_scores={"SUSPICIOUS": 0.7}),
            threat_category="SUSPICIOUS",
            tower_scores=TowerScores(text=30.0, url=20.0, header=25.0),
            text_analysis=TextAnalysis(),
            header_analysis=HeaderAnalysis(),
            iocs=IOCs(),
            reasons=[],
            model_metadata=ModelMetadata(text_mode="rules_only", model_versions={}, latency_ms=5.0),
            generated_at="2026-09-06T00:00:00Z"
        )
        json1 = result.to_canonical_json()
        json2 = result.to_canonical_json()
        assert json1 == json2

    def test_config_loaded(self):
        assert "fusion" in CONFIG
        assert "text_model" in CONFIG


class TestFixtures:
    FIXTURES_DIR = Path(__file__).parent / "fixtures"

    def test_all_fixtures_exist(self):
        for i in range(1, 11):
            fixture_path = self.FIXTURES_DIR / f"fixture_{i:02d}_*.json"
            files = list(self.FIXTURES_DIR.glob(f"fixture_{i:02d}_*.json"))
            assert len(files) == 1, f"Fixture {i} not found or duplicated"

    def test_fixtures_parse(self):
        fixtures_dir = Path(__file__).parent / "fixtures"
        for fixture_file in fixtures_dir.glob("fixture_*.json"):
            with open(fixture_file) as f:
                data = json.load(f)
            email = ParsedEmail(**data)
            assert email.message_id == data.get("message_id", "")


class TestDevice:
    def test_device_is_cpu_or_cuda(self):
        assert DEVICE in ("cpu", "cuda")
