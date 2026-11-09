"""Config , path helpers , reproducibility."""
from __future__ import annotations

import os
import random
from pathlib import Path

import yaml


def load_config(path: str | Path = "configs/data.yaml", drive_root: str | None = None) -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f)
    root = Path(drive_root or os.environ.get("ET_DRIVE_ROOT") or cfg["drive_root"])
    cfg["drive_root"] = str(root)
    cfg["abs"] = {k: str(root / v) for k, v in cfg["paths"].items()}
    return cfg


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass