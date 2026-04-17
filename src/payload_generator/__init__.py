"""
Context-aware, retrieval-augmented payload candidate generation (lab evaluation only).

**Primary operator path:** you describe a request as JSON, run generation here (or via
``scripts/generate_payload_batch.py``), paste payloads into Burp Intruder manually, run
the attack in Burp, export results, then normalize and aggregate in Python. Nothing in
this package connects to Burp or sends HTTP.

This package wires four explicit stages:

1. **Seed retrieval** — family-filtered rows from enriched CSV, ranked by
   :mod:`seed_retrieval` (metadata + context overlap; no external index).

2. **Candidate generation** — **hybrid** pipeline: constrained structural composition
   (slot filling + **named deterministic transforms**) over retrieved seeds. No neural
   or remote backends; behavior is offline and auditable.

3. **Candidate validation** — delegates to :class:`payload_validator.PayloadValidator`.

4. **Candidate ranking** — implemented in :mod:`payload_ranker` (:class:`CandidateRanker`).

**Separation from the contextual bandit:** Strategy selection for experiment arm **D**
lives in :mod:`adaptive_controller`. This package **only** produces and ranks
candidates given a :class:`GenerationRequest` (including a chosen family). That
split keeps the thesis narrative clear: the bandit addresses *which policy* to
apply; the generator addresses *how to instantiate payloads* under that policy.

**Deterministic retrieval:** Scores and primary ordering are fixed given CSV rows
and context so ablations and chapter results are reproducible. A seeded PRNG
perturbs **ties only** among equal scores—never arbitrary byte emission.

**Scope / ethics:** For **authorized web security labs** and offline evaluation only.
No automatic deployment to Burp, no network listeners, no exploitation orchestration.

Package layout
--------------
``schemas.py`` — request/seed/candidate datatypes. ``_utils.py`` — shared helpers.
``intruder_export.py`` — Intruder line sanitization + ranked audit CSV (arms C/D, CLI).
``retriever.py`` — CSV seed retrieval. ``hybrid.py`` — deterministic transform chains.
``pipeline.py`` — permissive validator + orchestration. Import from
``src.payload_generator`` as before; external import paths are unchanged.
"""

from __future__ import annotations

from ..payload_ranker import (
    CandidateRanker,
    HeuristicLexicalRanker,
    MultiFactorExplainableRanker,
)
from .hybrid import HybridCandidateGenerator
from .intruder_export import (
    RANKED_AUDIT_FIELDNAMES,
    sanitize_intruder_lines,
    write_ranked_generative_audit_csv,
)
from .pipeline import PayloadGenerationPipeline, PermissiveLabValidator
from .retriever import EnrichedCsvSeedRetriever, SeedRetriever
from .schemas import (
    ExplanationStep,
    GenerationRequest,
    GenerativeCandidate,
    RetrievedSeed,
)

__all__ = [
    "CandidateRanker",
    "EnrichedCsvSeedRetriever",
    "ExplanationStep",
    "GenerationRequest",
    "GenerativeCandidate",
    "HeuristicLexicalRanker",
    "HybridCandidateGenerator",
    "MultiFactorExplainableRanker",
    "PayloadGenerationPipeline",
    "PermissiveLabValidator",
    "RANKED_AUDIT_FIELDNAMES",
    "RetrievedSeed",
    "SeedRetriever",
    "sanitize_intruder_lines",
    "write_ranked_generative_audit_csv",
]
