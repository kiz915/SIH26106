import os
import torch
from pathlib import Path
from typing import Any
import yaml


def _get_device() -> str:
    if os.environ.get("CUDA_VISIBLE_DEVICES", "").strip() == "":
        return "cpu"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


DEVICE = _get_device()

BASE_DIR = Path(__file__).parent.parent
CONFIG_PATH = os.environ.get("ML_CONFIG_PATH", str(BASE_DIR / "configs" / "ml.yaml"))

DEFAULT_CONFIG: dict[str, Any] = {
    "text_model": {
        "mode": "rules_only",
        "local_files_only": True,
        "max_length": 512,
        "hybrid_weights": {"lexical": 0.65, "zero_shot": 0.35},
    },
    "fusion": {
        "strategy": "weighted",
        "weights": {"text": 0.40, "url": 0.30, "header": 0.30},
    },
    "risk_levels": {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0},
    "explainability": {
        "max_flagged_spans": 5,
        "max_anomalies": 5,
        "span_highlight_method": "lexicon",
    },
}


def load_config(config_path: str | None = CONFIG_PATH) -> dict[str, Any]:
    """Load optional YAML overrides while keeping local rules-only operation usable."""
    if not config_path or not Path(config_path).is_file():
        return DEFAULT_CONFIG.copy()

    with open(config_path, "r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f) or {}
    return {**DEFAULT_CONFIG, **loaded}


CONFIG = load_config()
