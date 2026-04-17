"""Request/seed/candidate datatypes for the generation pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..context_extractor import RequestContext
from ..payload_validator import PayloadCandidate


@dataclass(frozen=True)
class GenerationRequest:
    """
    Full request to the generation pipeline.

    Attributes:
        context: Normalized HTTP / insertion context from Burp export or fixtures.
        family: Target payload family (align with ``kb_family`` in ``enriched_payloads.csv``).
        k_seeds: Number of seed rows to retrieve.
        n_candidates: Soft target for composed candidates before validation/ranking.
        lab_run_id: Optional id for logging / reproducibility notes.
        options: Optional flags such as ``random_seed`` (int), ``max_payload_len`` (int),
            ``generator_mode`` (str, e.g. from arm **D** for thesis logging),
            ``adaptive_reward_seed_payloads`` (``list[str]``) — high-reward payloads from a prior
            arm **C** Intruder run; merged ahead of KB retrieval unless ``adaptive_reward_seeds_only``
            is true (then **no** KB seeds; see :meth:`PayloadGenerationPipeline._retrieve_generate_validate`).
            ``deterministic_transform_order`` (``bool``) — if true, hybrid chains run in sorted order (no shuffle).
    """

    context: RequestContext
    family: str
    k_seeds: int = 5
    n_candidates: int = 12
    lab_run_id: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RetrievedSeed:
    """One knowledge-base row selected to condition generation."""

    seed_id: str
    payload: str
    score: float
    row_metadata: dict[str, Any] = field(default_factory=dict)
    # Interpretable components from :mod:`seed_retrieval` (thesis / ablation tables).
    score_breakdown: dict[str, float] = field(default_factory=dict)


@dataclass
class ExplanationStep:
    """One step in the generation trace (thesis / XAI-friendly)."""

    step: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class GenerativeCandidate:
    """
    Rich candidate: payload string plus lineage, transforms, and scoring hooks.

    Use :meth:`to_payload_candidate` when interfacing with :class:`PayloadValidator`
    or :mod:`evaluation` trial records.
    """

    value: str
    family: str
    retrieval_ids: list[str]
    transforms: list[str]
    explanation: list[ExplanationStep]
    metadata: dict[str, Any] = field(default_factory=dict)
    rank_score: float | None = None
    rank_explanation: dict[str, float] | None = None

    def to_payload_candidate(self, source_label: str = "generative") -> PayloadCandidate:
        """Narrow view for validation and experiment tables."""
        extra: dict[str, Any] = {
            "family": self.family,
            "retrieval_ids": list(self.retrieval_ids),
            "transforms": list(self.transforms),
            "explanation": [
                {"step": e.step, "detail": e.detail, "data": dict(e.data)} for e in self.explanation
            ],
            "rank_score": self.rank_score,
            "rank_explanation": dict(self.rank_explanation) if self.rank_explanation else None,
        }
        extra.update(self.metadata)
        return PayloadCandidate(value=self.value, source_label=source_label, extra=extra)
