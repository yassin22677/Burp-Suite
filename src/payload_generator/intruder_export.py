"""Intruder-friendly text lines and audit CSV rows for ranked :class:`GenerativeCandidate` lists."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .schemas import GenerativeCandidate

RANKED_AUDIT_FIELDNAMES: tuple[str, ...] = (
    "line_index",
    "payload",
    "family",
    "rank_score",
    "retrieval_ids",
    "transforms",
    "explanation_json",
    "rank_explanation_json",
    "metadata_json",
)


def sanitize_intruder_lines(values: Iterable[str]) -> list[str]:
    """One payload per line: normalize CRLF and collapse embedded newlines to spaces."""
    out: list[str] = []
    for line in values:
        line = str(line).replace("\r\n", "\n").replace("\r", "\n")
        if "\n" in line:
            line = " ".join(line.splitlines())
        out.append(line)
    return out


def generative_candidate_audit_row(i: int, c: GenerativeCandidate) -> dict[str, Any]:
    """Single CSV row dict for one ranked candidate (arm C/D audit + CLI ``--csv-out``)."""
    return {
        "line_index": i,
        "payload": c.value,
        "family": c.family,
        "rank_score": c.rank_score,
        "retrieval_ids": ";".join(c.retrieval_ids),
        "transforms": ";".join(c.transforms),
        "explanation_json": json.dumps(
            [{"step": e.step, "detail": e.detail, "data": dict(e.data)} for e in c.explanation],
            ensure_ascii=False,
        ),
        "rank_explanation_json": json.dumps(c.rank_explanation or {}, ensure_ascii=False),
        "metadata_json": json.dumps(c.metadata, ensure_ascii=False),
    }


def write_ranked_generative_audit_csv(path: Path, ranked: list[GenerativeCandidate]) -> None:
    """Write the standard ranked-candidate audit CSV (same schema everywhere)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(RANKED_AUDIT_FIELDNAMES), extrasaction="ignore")
        w.writeheader()
        for i, c in enumerate(ranked):
            w.writerow(generative_candidate_audit_row(i, c))
