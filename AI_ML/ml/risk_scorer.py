"""Risk scoring and fusion strategies for combining tower scores."""

from typing import Protocol

from ml.config import CONFIG


class FusionStrategy(Protocol):
    """Protocol for risk score fusion strategies."""

    def fuse(self, text: float, url: float, header: float, features: dict) -> float:
        """Fuse tower scores into a final risk score."""
        ...


class WeightedFusion:
    """Weighted sum fusion with boost and cap rules."""

    def __init__(self):
        cfg = CONFIG.get("fusion", {})
        self.weights = cfg.get("weights", {"text": 0.40, "url": 0.30, "header": 0.30})
        self.boost_threshold = cfg.get("boost_threshold", 90.0)
        self.boost_floor = cfg.get("boost_floor", 60.0)
        self.cap_threshold_text = cfg.get("cap_threshold_text", 20.0)

    def fuse(self, text: float, url: float, header: float, features: dict) -> float:
        """Apply weighted fusion with boost and cap rules."""
        weighted = (
            text * self.weights["text"] +
            url * self.weights["url"] +
            header * self.weights["header"]
        )

        if text >= self.boost_threshold or url >= self.boost_threshold or header >= self.boost_threshold:
            weighted = max(weighted, self.boost_floor)

        auth_results = features.get("auth_results")
        all_urls = features.get("urls", [])
        if auth_results:
            spf = auth_results.get("spf", "none")
            dkim = auth_results.get("dkim", "none")
            dmarc = auth_results.get("dmarc", "none")
            if spf == "pass" and dkim == "pass" and dmarc == "pass" and not all_urls and text < self.cap_threshold_text:
                weighted = min(weighted, 15.0)

        return min(100.0, max(0.0, weighted))


class XGBoostFusion:
    """XGBoost-based fusion (stub for future implementation)."""

    def __init__(self):
        self.model = None

    def fuse(self, text: float, url: float, header: float, features: dict) -> float:
        """Placeholder - returns weighted average until XGBoost model is trained."""
        cfg = CONFIG.get("fusion", {})
        weights = cfg.get("weights", {"text": 0.40, "url": 0.30, "header": 0.30})
        return min(100.0, max(0.0,
            text * weights["text"] + url * weights["url"] + header * weights["header"]
        ))


def get_fusion_strategy() -> FusionStrategy:
    """Factory to get the configured fusion strategy."""
    cfg = CONFIG.get("fusion", {})
    strategy_name = cfg.get("strategy", "weighted")
    if strategy_name == "xgboost":
        return XGBoostFusion()
    return WeightedFusion()


def score_to_risk_level(score: float) -> str:
    """Convert numeric score to risk level.
    
    Config uses UPPER bounds: LOW < 25, MEDIUM < 50, HIGH < 75, CRITICAL <= 100
    """
    cfg = CONFIG.get("risk_levels", {})
    low_threshold = cfg.get("LOW", 25.0)
    medium_threshold = cfg.get("MEDIUM", 50.0)
    high_threshold = cfg.get("HIGH", 75.0)
    
    if score >= high_threshold:
        return "CRITICAL"
    elif score >= medium_threshold:
        return "HIGH"
    elif score >= low_threshold:
        return "MEDIUM"
    return "LOW"
