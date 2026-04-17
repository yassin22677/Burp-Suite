"""
Payload **ranking** (separate from generation and validation).

Consumes **valid** candidates only (the pipeline should filter before calling
:class:`CandidateRanker`). Uses a small :class:`typing.Protocol` so this module
does not import :mod:`payload_generator`, avoiding circular imports while keeping
the thesis story clean: generator produces, validator gates, ranker orders.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .context_extractor import RequestContext


@runtime_checkable
class RankableGenerativeCandidate(Protocol):
    """
    Structural type for objects produced by the generative pipeline.

    Any class with these attributes (e.g. :class:`payload_generator.GenerativeCandidate`)
    is rankable without inheritance.
    """

    value: str
    family: str
    transforms: list[str]
    metadata: Mapping[str, Any]
    rank_score: float | None
    rank_explanation: dict[str, float] | None


class CandidateRanker(ABC):
    """Assign scores and sort candidates; must not mutate payload strings."""

    @abstractmethod
    def rank(
        self,
        candidates: Sequence[RankableGenerativeCandidate],
        context: RequestContext,
    ) -> list[RankableGenerativeCandidate]:
        """Return sorted best-first; set ``rank_score`` and ``rank_explanation``."""


class HeuristicLexicalRanker(CandidateRanker):
    """
    Explainable baseline: prefers moderate length and higher character diversity.

    Thesis: report ``rank_explanation`` as additive feature contributions.
    """

    def __init__(self, target_len: int = 120) -> None:
        self._target_len = target_len

    def rank(
        self,
        candidates: Sequence[RankableGenerativeCandidate],
        context: RequestContext,
    ) -> list[RankableGenerativeCandidate]:
        _ = context
        scored: list[RankableGenerativeCandidate] = []
        for c in candidates:
            L = len(c.value)
            len_term = -abs(L - self._target_len) / max(self._target_len, 1)
            div_term = min(len(set(c.value)) / max(L, 1), 1.0)
            diversity = div_term * 2.0
            score = float(len_term + diversity)
            breakdown = {"length_term": float(len_term), "char_diversity_term": float(diversity)}
            c.rank_score = score
            c.rank_explanation = breakdown
            scored.append(c)
        scored.sort(
            key=lambda x: x.rank_score if x.rank_score is not None else float("-inf"),
            reverse=True,
        )
        return scored


def _context_tokens(ctx: RequestContext) -> set[str]:
    parts = re.split(r"/+", ctx.path.strip("/"))
    s = {p.lower() for p in parts if len(p) >= 2}
    for pm in ctx.parameter_tags:
        s.add(pm.name.lower())
    return {x for x in s if x}


def _bigram_novelty_ratio(s: str) -> float:
    if len(s) < 2:
        return 0.0
    bi = [s[i : i + 2] for i in range(len(s) - 1)]
    return len(set(bi)) / len(bi)


def _structural_diversity_score(s: str) -> float:
    """Normalized count of structurally interesting codepoints (0..1 scale)."""
    if not s:
        return 0.0
    interest = sum(
        1
        for c in s
        if c in "%'\"<>;|&`{}[]\\$\n\r\t" or (not c.isalnum() and not c.isspace())
    )
    return min(interest / max(len(s), 1) * 4.0, 1.0)


_FAM_TRANSFORM_PREFIXES: dict[str, tuple[str, ...]] = {
    "sql": ("sql_", "enc_", "slot_"),
    "xss": ("xss_", "enc_", "slot_"),
    "encoded_attack": ("enc_", "slot_"),
    "cmd": ("cmd_", "slot_", "enc_"),
    "other": ("generic_", "slot_", "enc_"),
}


def _transform_family_alignment(family: str, transforms: Sequence[str]) -> float:
    fam = (family or "other").lower().replace(" ", "_")
    prefs = _FAM_TRANSFORM_PREFIXES.get(fam, _FAM_TRANSFORM_PREFIXES["other"])
    if not transforms:
        return 0.0
    hits = sum(1 for t in transforms if any(str(t).startswith(p) for p in prefs))
    return hits / len(transforms)


class MultiFactorExplainableRanker(CandidateRanker):
    """
    Multi-factor **linear** score with explicit breakdown (thesis-friendly).

    Components (each in roughly [0,1] before weighting):
    - **context_compat**: token overlap between payload and path/parameter names.
    - **lexical_novelty**: bigram uniqueness ratio (diversity vs repetition).
    - **structural_diversity**: density of delimiter / operator-like characters.
    - **family_transform_alignment**: fraction of transform ids matching the
      expected prefix families for the stated payload family.

    Weights sum to 1.0 by default; adjust for ablation studies.
    """

    def __init__(
        self,
        w_context: float = 0.28,
        w_novelty: float = 0.27,
        w_structure: float = 0.22,
        w_transforms: float = 0.23,
    ) -> None:
        total = w_context + w_novelty + w_structure + w_transforms
        if total <= 0:
            raise ValueError("Sum of weights must be positive.")
        self._w_c = w_context / total
        self._w_n = w_novelty / total
        self._w_s = w_structure / total
        self._w_t = w_transforms / total

    def rank(
        self,
        candidates: Sequence[RankableGenerativeCandidate],
        context: RequestContext,
    ) -> list[RankableGenerativeCandidate]:
        kws = _context_tokens(context)
        ct = (context.content_type or "").lower()
        scored: list[RankableGenerativeCandidate] = []
        for c in candidates:
            v = c.value or ""
            low = v.lower()

            if kws:
                hits = sum(1 for k in kws if k in low)
                context_compat = hits / len(kws)
            else:
                context_compat = 0.35

            if "json" in ct and "{" in v[:200]:
                context_compat = min(1.0, context_compat + 0.12)
            if ("form" in ct or "urlencoded" in ct) and "=" in v and "&" in v:
                context_compat = min(1.0, context_compat + 0.1)

            novelty = _bigram_novelty_ratio(v)
            structure = _structural_diversity_score(v)
            t_align = _transform_family_alignment(c.family, c.transforms)

            contrib_c = self._w_c * context_compat
            contrib_n = self._w_n * novelty
            contrib_s = self._w_s * structure
            contrib_t = self._w_t * t_align
            total = contrib_c + contrib_n + contrib_s + contrib_t

            c.rank_score = float(total)
            c.rank_explanation = {
                "context_compat_raw": float(context_compat),
                "lexical_novelty_raw": float(novelty),
                "structural_diversity_raw": float(structure),
                "family_transform_alignment_raw": float(t_align),
                "weighted_context_compat": float(contrib_c),
                "weighted_lexical_novelty": float(contrib_n),
                "weighted_structural_diversity": float(contrib_s),
                "weighted_transform_alignment": float(contrib_t),
            }
            scored.append(c)

        scored.sort(
            key=lambda x: x.rank_score if x.rank_score is not None else float("-inf"),
            reverse=True,
        )
        return scored
