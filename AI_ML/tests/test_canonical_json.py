"""Tests for canonical JSON determinism (for Team 4 blockchain hashing)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.schemas import AnalysisResult, Classification, TextAnalysis, HeaderAnalysis, IOCs, ModelMetadata, TowerScores


class TestCanonicalJson:
    def _make_result(self):
        return AnalysisResult(
            message_id="<test@example.com>",
            fraud_score=25.0,
            risk_level="MEDIUM",
            classification=Classification(
                label="SUSPICIOUS",
                confidence=0.7,
                all_scores={"SUSPICIOUS": 0.7, "LEGITIMATE": 0.3}
            ),
            threat_category="SUSPICIOUS",
            tower_scores=TowerScores(text=30.0, url=20.0, header=25.0),
            text_analysis=TextAnalysis(),
            header_analysis=HeaderAnalysis(),
            iocs=IOCs(),
            reasons=[],
            model_metadata=ModelMetadata(
                text_mode="rules_only",
                model_versions={"test": "1.0"},
                latency_ms=5.0
            ),
            generated_at="2026-09-06T00:00:00Z"
        )

    def test_canonical_json_deterministic(self):
        result1 = self._make_result()
        result2 = self._make_result()
        json1 = result1.to_canonical_json()
        json2 = result2.to_canonical_json()
        assert json1 == json2

    def test_canonical_json_byte_identical_twice(self):
        result = self._make_result()
        json_first = result.to_canonical_json()
        json_second = result.to_canonical_json()
        assert json_first == json_second

    def test_canonical_json_same_input_same_output(self):
        data = {
            "message_id": "<test@example.com>",
            "fraud_score": 50.0,
            "risk_level": "HIGH",
            "classification": Classification(
                label="PHISHING",
                confidence=0.95,
                all_scores={"PHISHING": 0.95, "LEGITIMATE": 0.05}
            ),
            "threat_category": "PHISHING",
            "tower_scores": TowerScores(text=60.0, url=70.0, header=20.0),
            "text_analysis": TextAnalysis(),
            "header_analysis": HeaderAnalysis(),
            "iocs": IOCs(),
            "reasons": [],
            "model_metadata": ModelMetadata(
                text_mode="rules_only",
                model_versions={},
                latency_ms=10.0
            ),
            "generated_at": "2026-09-06T12:00:00Z"
        }
        result1 = AnalysisResult(**data)
        result2 = AnalysisResult(**data)
        assert result1.to_canonical_json() == result2.to_canonical_json()

    def test_canonical_json_excludes_generated_at(self):
        result = self._make_result()
        canonical = result.to_canonical_dict()
        assert "generated_at" not in canonical

    def test_canonical_json_excludes_latency(self):
        result = self._make_result()
        canonical = result.to_canonical_dict()
        assert canonical["model_metadata"]["latency_ms"] == 0.0

    def test_canonical_json_sorted_keys(self):
        result = self._make_result()
        canonical_str = result.to_canonical_json()
        parsed = json.loads(canonical_str)
        keys = list(parsed.keys())
        assert keys == sorted(keys)
