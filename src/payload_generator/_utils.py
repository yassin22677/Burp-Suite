"""Small deterministic helpers shared by seed retrieval and hybrid generation."""

from __future__ import annotations

import random

from .schemas import GenerationRequest


def _normalize_family(family: str) -> str:
    return (family or "").strip().lower().replace(" ", "_")


def _rng_for_request(request: GenerationRequest) -> random.Random:
    """
    Seeded RNG for tie-breaking in retrieval and template order only.

    Payload bytes come from seeds and named transforms, not from this RNG.
    """
    seed = request.options.get("random_seed")
    if seed is None:
        seed = hash((request.context.request_id, request.lab_run_id or "", request.family)) % (2**32)
    return random.Random(int(seed))
