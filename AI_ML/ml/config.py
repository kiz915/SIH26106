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


def load_config(config_path: str = CONFIG_PATH) -> dict[str, Any]:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


CONFIG = load_config()
