"""Permissive validator stub and :class:`PayloadGenerationPipeline` orchestration."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..context_extractor import RequestContext
from ..payload_ranker import CandidateRanker
from ..payload_validator import (
    LabPayloadValidator,
    PayloadCandidate,
    PayloadValidator,
    ValidationFinding,
    ValidationResult,
    Severity,
)
from .hybrid import HybridCandidateGenerator
from .schemas import GenerationRequest, GenerativeCandidate, RetrievedSeed
from .retriever import SeedRetriever


def _validation_metadata_block(validator_name: str, vr: ValidationResult) -> dict[str, Any]:
    sev_counts: dict[str, int] = {}
    for f in vr.findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
    return {
        "is_valid": True,
        "validator_class": validator_name,
        "finding_count": len(vr.findings),
        "finding_counts_by_severity": sev_counts,
        "findings": [
            {"code": f.code, "message": f.message, "severity": f.severity.value}
            for f in vr.findings
        ],
        "metrics": dict(vr.metrics),
    }


# ---------------------------------------------------------------------------
# 3) Validation (stub + protocol)
# ---------------------------------------------------------------------------


class PermissiveLabValidator(PayloadValidator):
    """
    Smoke-test validator: always accepts candidates (single INFO finding).

    Pass explicitly to :class:`PayloadGenerationPipeline` when you need to bypass
    :class:`LabPayloadValidator` policy (e.g. quick pipeline wiring). Default
    pipeline uses :class:`LabPayloadValidator` instead.
    """

    def validate(
        self,
        candidate: PayloadCandidate,
        context: RequestContext | None = None,
    ) -> ValidationResult:
        _ = context
        return ValidationResult(
            is_valid=True,
            findings=[
                ValidationFinding(
                    code="STUB_PERMISSIVE",
                    message="PermissiveLabValidator accepts all candidates for pipeline testing.",
                    severity=Severity.INFO,
                )
            ],
            metrics={"validator": "permissive_lab"},
        )


# ---------------------------------------------------------------------------
# Orchestration (ranking: see payload_ranker.py)
# ---------------------------------------------------------------------------


class PayloadGenerationPipeline:
    """
    End-to-end: retrieve → generate → validate → rank.

    Validation is a **mandatory gate**: invalid candidates are dropped before ranking,
    so metrics reflect policy-compliant strings only. **Default validator:**
    :class:`LabPayloadValidator` when ``validator`` is omitted (keyword-only).
    Pass ``validator=PermissiveLabValidator()`` for smoke tests only.

    Validation populates ``metadata["validation"]`` on each kept candidate; the ranker
    consumes valid rows only and does not depend on validator internals.
    """

    def __init__(
        self,
        retriever: SeedRetriever,
        generator: HybridCandidateGenerator,
        ranker: CandidateRanker,
        *,
        validator: PayloadValidator | None = None,
    ) -> None:
        self._retriever = retriever
        self._generator = generator
        self._ranker = ranker
        self._validator = validator if validator is not None else LabPayloadValidator()

    def _retrieve_generate_validate(
        self, request: GenerationRequest
    ) -> tuple[list[RetrievedSeed], list[GenerativeCandidate], list[GenerativeCandidate]]:
        raw_bonus = request.options.get("adaptive_reward_seed_payloads")
        bonus_list: list[str] = []
        if isinstance(raw_bonus, (list, tuple)):
            bonus_list = [str(p).strip() for p in raw_bonus if str(p).strip()]

        if bonus_list:
            bonus_seeds: list[RetrievedSeed] = []
            for i, p in enumerate(bonus_list):
                bonus_seeds.append(
                    RetrievedSeed(
                        seed_id=f"reward_prior_{i}",
                        payload=p,
                        score=float(1_000_000 - i),
                        row_metadata={"source": "prior_arm_c_trial", "reward_seed_rank": i},
                        score_breakdown={
                            "prior_trial_reward": float(1_000_000 - i),
                            "total_weighted_score": float(1_000_000 - i),
                        },
                    )
                )
            seeds_only = bool(request.options.get("adaptive_reward_seeds_only"))
            if seeds_only:
                seeds = bonus_seeds
            else:
                k_rem = max(0, int(request.k_seeds) - len(bonus_seeds))
                sub_opts = dict(request.options)
                sub_opts.pop("adaptive_reward_seed_payloads", None)
                sub_req = replace(request, k_seeds=k_rem, options=sub_opts)
                kb_seeds = self._retriever.retrieve(sub_req) if k_rem > 0 else []
                seeds = bonus_seeds + kb_seeds
        else:
            seeds = self._retriever.retrieve(request)
        raw = self._generator.generate(request, seeds)
        valid: list[GenerativeCandidate] = []
        validator_name = type(self._validator).__name__
        for cand in raw:
            vr = self._validator.validate(cand.to_payload_candidate(), request.context)
            if vr.is_valid:
                cand.metadata["validation"] = _validation_metadata_block(validator_name, vr)
                valid.append(cand)
        return seeds, raw, valid

    def run(self, request: GenerationRequest) -> list[GenerativeCandidate]:
        _, _, valid = self._retrieve_generate_validate(request)
        return self._ranker.rank(valid, request.context)

    def run_with_debug(self, request: GenerationRequest) -> tuple[list[GenerativeCandidate], dict[str, Any]]:
        """
        Same as :meth:`run`, plus a JSON-serializable trace for thesis debugging (arm C).

        Proves retrieval → generation → validation → ranking are distinct stages.
        """
        seeds, raw, valid = self._retrieve_generate_validate(request)
        ranked = self._ranker.rank(valid, request.context)
        debug: dict[str, Any] = {
            "experiment_arm": str(request.options.get("thesis_arm") or "C_generated"),
            "lab_run_id": request.lab_run_id,
            "family": request.family,
            "adaptive_reward_seeds_only": bool(request.options.get("adaptive_reward_seeds_only")),
            "deterministic_transform_order": bool(request.options.get("deterministic_transform_order")),
            "retrieved_seed_count": len(seeds),
            "retrieved_seeds": [
                {"seed_id": s.seed_id, "score": s.score, "payload_preview": (s.payload or "")[:200]}
                for s in seeds
            ],
            "raw_generated_count": len(raw),
            "raw_generated_previews": [(c.value or "")[:200] for c in raw[:25]],
            "post_validation_count": len(valid),
            "ranked_count": len(ranked),
            "ranked_final_previews": [(c.value or "")[:200] for c in ranked[:25]],
            "first_ranked_transforms": list(ranked[0].transforms) if ranked else [],
        }
        return ranked, debug