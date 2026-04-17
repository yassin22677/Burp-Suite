"""CSV-backed seed retrieval (:class:`SeedRetriever`, :class:`EnrichedCsvSeedRetriever`)."""

from __future__ import annotations

import csv
from abc import ABC, abstractmethod
from pathlib import Path

from ..seed_retrieval import compute_enriched_seed_score
from .schemas import GenerationRequest, RetrievedSeed
from ._utils import _normalize_family, _rng_for_request

# ---------------------------------------------------------------------------
# 1) Seed retrieval
# ---------------------------------------------------------------------------


class SeedRetriever(ABC):
    """Retrieve conditioning seeds for RAG-style generation."""

    @abstractmethod
    def retrieve(self, request: GenerationRequest) -> list[RetrievedSeed]:
        """Return up to ``request.k_seeds`` seeds for this request."""


class EnrichedCsvSeedRetriever(SeedRetriever):
    """
    Deterministic, **family-filtered** retrieval from ``enriched_payloads.csv``.

    Uses :func:`seed_retrieval.compute_enriched_seed_score` — a deterministic weighted
    mix of CSV metadata (``heuristic_pattern_band``, ``encoding_surface_class``,
    ``percent_encoding_density``, ``label_consistency_flag``, length) and request
    context overlap.  See :mod:`seed_retrieval` for weights and term definitions.
    """

    def __init__(self, csv_path: str | Path, payload_column: str = "payload") -> None:
        self._path = Path(csv_path)
        self._payload_column = payload_column
        self._rows: list[dict[str, str]] | None = None

    def _load_rows(self) -> list[dict[str, str]]:
        if self._rows is None:
            with self._path.open(newline="", encoding="utf-8") as f:
                self._rows = list(csv.DictReader(f))
        return self._rows

    def retrieve(self, request: GenerationRequest) -> list[RetrievedSeed]:
        fam = _normalize_family(request.family)
        rows = self._load_rows()
        pool = [r for r in rows if _normalize_family(r.get("kb_family", r.get("category", ""))) == fam]
        if not pool:
            return []

        scored: list[tuple[float, dict[str, str], dict[str, float]]] = []
        for r in pool:
            payload = r.get(self._payload_column, "") or ""
            sc, breakdown = compute_enriched_seed_score(r, payload, request.context, fam)
            scored.append((sc, r, breakdown))
        # Deterministic ordering: higher score first, then stable row id, then payload prefix.
        scored.sort(
            key=lambda item: (
                -item[0],
                str(item[1].get("row_id", item[1].get("rowid", ""))),
                (item[1].get(self._payload_column) or "")[:48],
            )
        )
        rng = _rng_for_request(request)
        top = scored[: max(request.k_seeds * 3, request.k_seeds)]
        # Reproducible tie exploration: shuffle within equal-score bands only.
        banded: list[tuple[float, dict[str, str], dict[str, float]]] = []
        i = 0
        while i < len(top):
            j = i + 1
            while j < len(top) and top[j][0] == top[i][0]:
                j += 1
            chunk = top[i:j]
            rng.shuffle(chunk)
            banded.extend(chunk)
            i = j
        picked_rows = banded[: request.k_seeds]

        seeds: list[RetrievedSeed] = []
        for sc, r, breakdown in picked_rows:
            sid = r.get("row_id", r.get("rowid", "")) or str(len(seeds))
            payload = r.get(self._payload_column, "") or ""
            meta = {k: r[k] for k in r if k != self._payload_column}
            meta["retrieval_score_breakdown"] = dict(breakdown)
            seeds.append(
                RetrievedSeed(
                    seed_id=str(sid),
                    payload=payload,
                    score=float(sc),
                    row_metadata=meta,
                    score_breakdown=dict(breakdown),
                )
            )
        return seeds
