"""
Resolve the repository root and put it on ``sys.path`` so ``import src.*`` works.

Intended for CLIs run as ``python scripts/<name>.py`` from any working directory
that still resolves ``parents[1]`` to the repo (the usual layout).
"""

from __future__ import annotations

import sys
from pathlib import Path


def repo_root() -> Path:
    """Directory that contains ``src/`` and ``scripts/``."""
    return Path(__file__).resolve().parents[1]


def ensure_repo_on_path() -> Path:
    """Return repo root after ensuring it is the first entry on ``sys.path``."""
    root = repo_root()
    s = str(root)
    if s not in sys.path:
        sys.path.insert(0, s)
    return root
