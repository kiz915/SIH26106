import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from config.config import FUSION_WEIGHTS, FUSION_STRATEGY

logger = logging.getLogger(__name__)

class FusionStrategy(ABC):
    @abstractmethod
    def fuse(self, scores: Dict[str, float], features: Optional[Dict[str, Any]] = None) -> float:
        """
        scores has keys 'nlp', 'url', 'header' with values 0-100
        features is optional dict of all extracted features (for ML-based fusion)
        Returns fused score 0-100
        """
        pass

class WeightedFusion(FusionStrategy):
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights if weights is not None else FUSION_WEIGHTS

    def fuse(self, scores: Dict[str, float], features: Optional[Dict[str, Any]] = None) -> float:
        weighted_sum = sum(scores[k] * self.weights[k] for k in self.weights if k in scores)
        
        # Boosting rule: if any component score >= 90, floor the result at 60
        if any(scores.get(k, 0) >= 90 for k in self.weights):
            weighted_sum = max(weighted_sum, 60.0)
            
        # Clamp to 0-100
        weighted_sum = max(0.0, min(100.0, weighted_sum))
        
        return float(round(weighted_sum, 1))

class XGBoostFusion(FusionStrategy):
    '''Stub for XGBoost-based meta-classifier fusion.
    
    Requires a trained XGBoost model. Falls back to WeightedFusion
    if no model is available. To train, see training/train_fusion.py (future).
    
    This stub satisfies the FusionStrategy interface and will use SHAP
    for explainability when the model is trained.
    '''
    def __init__(self, model_path: Optional[str] = None):
        self._model = None
        self._fallback = WeightedFusion()
        if model_path is not None:
            try:
                import xgboost as xgb
                import os
                if os.path.exists(model_path):
                    self._model = xgb.Booster()
                    self._model.load_model(model_path)
            except Exception as e:
                logger.warning(f"Failed to load XGBoost model from {model_path}: {e}")

    def fuse(self, scores: Dict[str, float], features: Optional[Dict[str, Any]] = None) -> float:
        if self._model is None:
            return self._fallback.fuse(scores, features)
        
        # Fallback for now since no model is trained
        return self._fallback.fuse(scores, features)

def get_fusion_strategy(name: Optional[str] = None) -> FusionStrategy:
    strategy_name = name if name is not None else FUSION_STRATEGY
    if strategy_name == 'xgboost':
        return XGBoostFusion()
    elif strategy_name == 'weighted':
        return WeightedFusion()
    else:
        logger.warning(f"Unknown fusion strategy '{strategy_name}'. Falling back to weighted.")
        return WeightedFusion()
