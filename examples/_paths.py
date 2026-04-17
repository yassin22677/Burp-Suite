"""Same path bootstrap as ``scripts/_repo_root.py`` for example programs."""

from __future__ import annotations

import sys
from pathlib import Path


def ensure_repo_on_path() -> Path:
    root = Path(__file__).resolve().parents[1]
    s = str(root)
    if s not in sys.path:
        sys.path.insert(0, s)
    return root
