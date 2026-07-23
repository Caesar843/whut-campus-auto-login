import sys
from pathlib import Path


def resource_path(relative_path: str) -> Path:
    root = Path(sys._MEIPASS) if hasattr(sys, "_MEIPASS") else Path(__file__).resolve().parents[2]
    path = root / relative_path
    if not path.is_file():
        raise FileNotFoundError(f"Application resource is missing: {relative_path}")
    return path
