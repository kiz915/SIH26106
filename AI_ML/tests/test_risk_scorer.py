"""Tests for risk scoring and fusion strategies."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.risk_scorer import WeightedFusion, XGBoostFusion, score_to_risk_level, get_fusion_strategy


class TestWeightedFusion:
    def setup_method(self):
        self.fusion = WeightedFusion()

    def test_basic_fusion(self):
        score = self.fusion.fuse(50.0, 50.0, 50.0, {})
        assert 49 <= score <= 51

    def test_boost_rule_any_tower_high(self):
        score = self.fusion.fuse(95.0, 10.0, 10.0, {})
        assert score >= 60.0

    def test_boost_rule_all_towers_high(self):
        score = self.fusion.fuse(90.0, 90.0, 90.0, {})
        assert score >= 60.0

    def test_cap_rule_legit_email(self):
        features = {
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "urls": []
        }
        score = self.fusion.fuse(15.0, 0.0, 0.0, features)
        assert score <= 15.0

    def test_cap_rule_not_triggered_with_urls(self):
        features = {
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "urls": ["http://suspicious.com"]
        }
        score = self.fusion.fuse(15.0, 0.0, 0.0, features)
        assert score == 6.0

    def test_cap_rule_not_triggered_high_text(self):
        features = {
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "urls": []
        }
        score = self.fusion.fuse(25.0, 0.0, 0.0, features)
        assert score == 10.0


class TestScoreToRiskLevel:
    def test_low(self):
        assert score_to_risk_level(10.0) == "LOW"
        assert score_to_risk_level(24.9) == "LOW"

    def test_medium(self):
        assert score_to_risk_level(30.0) == "MEDIUM"
        assert score_to_risk_level(49.0) == "MEDIUM"

    def test_high(self):
        assert score_to_risk_level(55.0) == "HIGH"
        assert score_to_risk_level(74.0) == "HIGH"

    def test_critical(self):
        assert score_to_risk_level(80.0) == "CRITICAL"
        assert score_to_risk_level(100.0) == "CRITICAL"


class TestGetFusionStrategy:
    def test_returns_weighted_by_default(self):
        strategy = get_fusion_strategy()
        assert isinstance(strategy, WeightedFusion)

    def test_returns_xgboost_when_configured(self):
        from ml import config
        original = config.CONFIG.get("fusion", {}).get("strategy")
        config.CONFIG["fusion"] = {"strategy": "xgboost"}
        strategy = get_fusion_strategy()
        assert isinstance(strategy, XGBoostFusion)
        if original:
            config.CONFIG["fusion"]["strategy"] = original
