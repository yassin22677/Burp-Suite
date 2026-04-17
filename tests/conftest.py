"""
Shared synthetic fixtures for offline pipeline tests (thesis / lab evaluation).

No Burp, no network. CSV and JSON blobs are minimal but structurally valid.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Import ``src.*`` when running ``pytest`` from the repository root.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def repo_root() -> Path:
    """Repository root (same directory that contains ``src/`` and ``tests/``)."""
    return REPO_ROOT


@pytest.fixture
def lab_request_dict() -> dict:
    """Minimal JSON-shaped export for :class:`RequestContextExtractor`."""
    return {
        "request_id": "test_ctx_01",
        "method": "POST",
        "url": "https://lab.example/api/items/search",
        "content_type": "application/json",
        "parameters": [
            {"name": "q", "location": "json", "declared_type": "string"},
            {"name": "limit", "location": "json", "declared_type": "int"},
        ],
    }


@pytest.fixture
def runner_ctx(lab_request_dict: dict):
    """Shared :class:`RequestContext` for runner / policy tests (avoids duplicate fixtures)."""
    from src.context_extractor import RequestContextExtractor

    return RequestContextExtractor().extract(lab_request_dict)


@pytest.fixture
def enriched_kb_path(tmp_path: Path) -> Path:
    """
    Tiny enriched-knowledge CSV compatible with :func:`seed_retrieval.compute_enriched_seed_score`.

    Two ``xss`` rows so retrieval can rank and return multiple seeds.
    """
    csv_text = (
        "row_id,payload,kb_family,category,label_consistency_flag,heuristic_pattern_band,"
        "encoding_surface_class,percent_encoding_density,char_len_computed,length\n"
        "0,<script>lab</script>,xss,xss,pattern_supports_family,script_tag_evidence,"
        "ascii_plain,0,20,20\n"
        "1,plain,xss,xss,no_keyword_pattern_matched,unknown,ascii_plain,0,5,5\n"
    )
    p = tmp_path / "enriched.csv"
    p.write_text(csv_text, encoding="utf-8")
    return p
