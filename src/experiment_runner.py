"""
End-to-end experiment orchestration for arms **A–D** (thesis / lab evaluation).

This module **coordinates** existing components; it does not reimplement retrieval,
generation, validation, ranking, bandit math, or aggregation. Execution remains
behind :class:`execution_backend.ExecutionBackend` (typically offline replay).

**Per arm (high level)**

- **A** (:attr:`ExperimentGroup.BASELINE_BURP`): user-supplied baseline payload strings
  (e.g. default Burp wordlist snippets). No knowledge-base retrieval.
- **B** (:attr:`ExperimentGroup.STATIC_DATASET`): raw ``payload`` column values from
  ``enriched_payloads.csv`` for a chosen ``kb_family`` (dataset replay, no transforms).
  Ordering is **row_id**-sorted (or seeded shuffle), **not** retrieval-ranked like arm C.
- **C** (:attr:`ExperimentGroup.GENERATED`): :class:`payload_generator.PayloadGenerationPipeline`
  with a fixed ``GenerationRequest.family`` (no adaptive arm selection). Uses **scored**
  retrieval plus named hybrid transforms—must not be fed the same Intruder file as arm B
  in thesis experiments.
- **D** (:attr:`ExperimentGroup.GENERATED_ADAPTIVE`): :class:`adaptive_controller.AdaptiveBanditController`
  selects a :class:`adaptive_controller.StrategyArm`; the runner maps it to
  ``GenerationRequest`` options, generates, executes **one top-ranked** candidate per
  bandit round, builds :class:`adaptive_controller.OutcomeMetrics` from replay outcomes,
  and calls :meth:`~adaptive_controller.AdaptiveBanditController.register_outcome`.

**Offline safety:** No HTTP clients and no Burp APIs here. An :class:`OutcomeProvider`
supplies parallel outcome dicts (as for :class:`~execution_backend.OfflineReplayExecutionBackend`).

**Optional scanner policy (orthogonal to arm D):** Set ``scanner_policy_selector`` on
:class:`ExperimentRunnerConfig` to a :class:`scanner_policy.ScannerPolicySelector`
subclass. The runner logs each decision to ``metadata_log`` and copies it into
:class:`~evaluation.TrialRecord` ``tags``. These are **named presets for thesis /
logging only**; they do **not** configure Burp, drive Intruder, or control any live
scanner (see :mod:`scanner_policy`).

**Metrics after a run:** :func:`summarize_trial_records` wraps
:func:`evaluation_pipeline.comparison_metrics_table` for per-arm thesis tables.

Minimal example (one context, all four arms, fixture outcomes)::

    from pathlib import Path
    from src.context_extractor import RequestContextExtractor
    from src.evaluation import ExperimentGroup
    from src.execution_backend import OfflineReplayExecutionBackend
    from src.experiment_runner import ExperimentRunner, ExperimentRunnerConfig
    from src.payload_generator import (
        EnrichedCsvSeedRetriever,
        HybridCandidateGenerator,
        MultiFactorExplainableRanker,
        PayloadGenerationPipeline,
    )

    ctx = RequestContextExtractor().extract(
        {"request_id": "r1", "url": "https://lab/x", "method": "GET"}
    )
    pipeline = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(Path("data/enriched_payloads.csv")),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
    )

    def outcomes(group, context, candidates):
        return [{"trial_status_code": 200, "trial_response_length": 100} for _ in candidates]

    cfg = ExperimentRunnerConfig(
        contexts=[ctx],
        arms=frozenset(e for e in ExperimentGroup),
        enriched_kb_path=Path("data/enriched_payloads.csv"),
        generation_pipeline=pipeline,
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=outcomes,
        baseline_status_code=200,
        baseline_response_length=500,
        baseline_burp_payloads=["admin", "test"],
        kb_static_family="xss",
        static_payload_limit=5,
    )
    result = ExperimentRunner(cfg).run()
    # result.trial_records, result.metadata_log
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, FrozenSet, Sequence

from .adaptive_controller import (
    AdaptiveBanditController,
    OutcomeMetrics,
    StrategyArm,
    arms_from_grid,
    outcome_to_reward,
)
from .context_extractor import RequestContext
from .evaluation import ExperimentGroup, TrialRecord
from .execution_backend import ExecutionBackend, ExecutionBatch
from .payload_generator import GenerationRequest, PayloadGenerationPipeline
from .payload_validator import PayloadCandidate
from .scanner_policy import ScannerPolicySelector, attach_decision_to_trial_tags

# Callable: (group, context, candidates) -> replay_outcome dicts, same length as candidates
OutcomeProviderFn = Callable[
    [ExperimentGroup, RequestContext, Sequence[PayloadCandidate]],
    list[dict[str, Any]],
]


def load_static_payloads_from_enriched_kb(
    kb_path: Path,
    family: str,
    *,
    limit: int,
    random_seed: int | None = None,
) -> list[str]:
    """
    Read raw ``payload`` strings for ``kb_family`` (or ``category``) from an enriched CSV.

    Deterministic when ``random_seed`` is ``None`` (sort by ``row_id``). Mirrors the
    logic of ``scripts/export_static_payload_batch.py`` for in-process use.
    """
    import random

    fam = (family or "").strip().lower().replace(" ", "_")
    with Path(kb_path).open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    pool: list[dict[str, str]] = []
    for r in rows:
        kb = (r.get("kb_family") or r.get("category") or "").strip().lower().replace(" ", "_")
        if kb == fam:
            pool.append(r)

    def _row_id_key(row: dict[str, str]) -> tuple:
        rid = row.get("row_id") or row.get("rowid") or ""
        try:
            return (0, int(str(rid).strip()))
        except ValueError:
            return (1, str(rid))

    if not pool:
        return []
    n = min(limit, len(pool))
    if random_seed is not None:
        rng = random.Random(int(random_seed))
        idx = list(range(len(pool)))
        rng.shuffle(idx)
        chosen = [pool[i] for i in idx[:n]]
    else:
        chosen = sorted(pool, key=_row_id_key)[:n]
    return [(r.get("payload") or "") for r in chosen]


def strategy_arm_to_generation_options(arm: StrategyArm) -> dict[str, Any]:
    """Map bandit :class:`StrategyArm` to ``GenerationRequest.options`` (explainable knobs)."""
    return {
        "generator_mode": arm.generator_mode,
    }


def _outcome_row_to_metrics(
    row: dict[str, Any],
    *,
    baseline_status_code: int | None,
    baseline_response_length: int | None,
) -> OutcomeMetrics:
    """Build :class:`OutcomeMetrics` for the bandit from one replay outcome dict."""

    def _int_opt(v: Any) -> int | None:
        if v is None or (isinstance(v, str) and not str(v).strip()):
            return None
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None

    ts = row.get("trial_status_code", row.get("status"))
    tl = row.get("trial_response_length", row.get("length"))
    return OutcomeMetrics(
        baseline_status_code=baseline_status_code,
        trial_status_code=_int_opt(ts),
        baseline_length=baseline_response_length,
        trial_length=_int_opt(tl),
        strong_abnormal=bool(row.get("strong_abnormal", row.get("is_abnormal", False))),
        moderate_differential=bool(row.get("moderate_differential", False)),
        invalid_candidate_batch=bool(row.get("invalid_candidate_batch", False)),
    )


@dataclass
class ExperimentRunnerConfig:
    """
    Configuration for :class:`ExperimentRunner`.

    ``outcome_provider`` must return one outcome dict per candidate (status/length
    and optional flags) for offline replay—typically mirroring Burp Intruder rows.
    """

    contexts: Sequence[RequestContext]
    arms: FrozenSet[ExperimentGroup]
    enriched_kb_path: Path
    generation_pipeline: PayloadGenerationPipeline
    execution_backend: ExecutionBackend
    outcome_provider: OutcomeProviderFn
    baseline_status_code: int | None = None
    baseline_response_length: int | None = None
    # Arm A
    baseline_burp_payloads: Sequence[str] = ()
    # Arm B
    kb_static_family: str = "xss"
    static_payload_limit: int = 10
    static_sample_seed: int | None = None
    # Arm C / shared generation
    generation_family: str = "xss"
    k_seeds: int = 5
    n_candidates: int = 8
    generation_random_seed: int | None = 42
    # Arm D
    adaptive_controller: AdaptiveBanditController | None = None
    d_rounds_per_context: int = 2
    strategy_families: Sequence[str] = ("sql", "xss")
    strategy_modes: Sequence[str] = ("hybrid", "template")
    # Optional: abstract scan-configuration preset (offline; see scanner_policy module)
    scanner_policy_selector: ScannerPolicySelector | None = None
    # Logging
    trial_id_prefix: str = "exp"


@dataclass
class ExperimentRunResult:
    """All :class:`TrialRecord` rows plus an append-only metadata log for analysis."""

    trial_records: list[TrialRecord] = field(default_factory=list)
    metadata_log: list[dict[str, Any]] = field(default_factory=list)


class ExperimentRunner:
    """
    Run selected experiment arms across all configured :class:`RequestContext` instances.
    """

    def __init__(self, config: ExperimentRunnerConfig) -> None:
        self._cfg = config
        self._batch_seq = 0
        self._controller: AdaptiveBanditController | None = None
        if ExperimentGroup.GENERATED_ADAPTIVE in config.arms:
            self._controller = config.adaptive_controller or AdaptiveBanditController(
                arms=arms_from_grid(config.strategy_families, config.strategy_modes),
            )

    def _log(self, entry: dict[str, Any]) -> None:
        self._result.metadata_log.append(entry)

    def _next_batch_prefix(self, group: ExperimentGroup, ctx: RequestContext, tag: str) -> str:
        p = f"{self._cfg.trial_id_prefix}_{self._batch_seq}_{group.value}_{ctx.request_id}_{tag}"
        self._batch_seq += 1
        return p

    def _materialize(
        self,
        *,
        group: ExperimentGroup,
        ctx: RequestContext,
        candidates: list[PayloadCandidate],
        outcomes: list[dict[str, Any]],
        log_tag: str,
        round_index: int | None = None,
        strategy_arm_label: str | None = None,
    ) -> list[TrialRecord]:
        if len(outcomes) != len(candidates):
            raise ValueError(
                f"outcome_provider returned {len(outcomes)} rows for {len(candidates)} candidates "
                f"(arm={group.value}, context={ctx.request_id})."
            )
        batch = ExecutionBatch(
            request_context=ctx,
            candidates=candidates,
            group=group,
            baseline_status_code=self._cfg.baseline_status_code,
            baseline_response_length=self._cfg.baseline_response_length,
            replay_outcomes=outcomes,
            trial_id_prefix=self._next_batch_prefix(group, ctx, log_tag),
        )
        trials = self._cfg.execution_backend.execute_batch(batch)
        self._maybe_attach_scanner_policy(
            trials,
            ctx,
            group,
            round_index=round_index,
            strategy_arm_label=strategy_arm_label,
        )
        return trials

    def _maybe_attach_scanner_policy(
        self,
        trials: list[TrialRecord],
        ctx: RequestContext,
        group: ExperimentGroup,
        *,
        round_index: int | None,
        strategy_arm_label: str | None,
    ) -> None:
        sel = self._cfg.scanner_policy_selector
        if sel is None:
            return
        decision = sel.select(
            ctx,
            experiment_group=group,
            round_index=round_index,
            strategy_arm_label=strategy_arm_label,
        )
        self._log(
            {
                "event": "scanner_policy_selected",
                "request_id": ctx.request_id,
                "experiment_arm": group.value,
                **decision.to_log_dict(),
            }
        )
        for t in trials:
            attach_decision_to_trial_tags(t.tags, decision)

    def _gen_options_base(self) -> dict[str, Any]:
        o: dict[str, Any] = {}
        if self._cfg.generation_random_seed is not None:
            o["random_seed"] = int(self._cfg.generation_random_seed)
        return o

    def _run_arm_a(self, ctx: RequestContext) -> list[TrialRecord]:
        payloads = list(self._cfg.baseline_burp_payloads)
        if not payloads:
            self._log(
                {
                    "arm": ExperimentGroup.BASELINE_BURP.value,
                    "request_id": ctx.request_id,
                    "event": "skipped",
                    "reason": "baseline_burp_payloads empty",
                }
            )
            return []
        cands = [
            PayloadCandidate(value=p, source_label="baseline_burp", experiment_group=ExperimentGroup.BASELINE_BURP.value)
            for p in payloads
        ]
        out = self._cfg.outcome_provider(ExperimentGroup.BASELINE_BURP, ctx, cands)
        trials = self._materialize(
            group=ExperimentGroup.BASELINE_BURP,
            ctx=ctx,
            candidates=cands,
            outcomes=out,
            log_tag="A",
        )
        self._log(
            {
                "arm": ExperimentGroup.BASELINE_BURP.value,
                "request_id": ctx.request_id,
                "event": "completed",
                "trial_count": len(trials),
            }
        )
        return trials

    def _run_arm_b(self, ctx: RequestContext) -> list[TrialRecord]:
        payloads = load_static_payloads_from_enriched_kb(
            self._cfg.enriched_kb_path,
            self._cfg.kb_static_family,
            limit=self._cfg.static_payload_limit,
            random_seed=self._cfg.static_sample_seed,
        )
        if not payloads:
            self._log(
                {
                    "arm": ExperimentGroup.STATIC_DATASET.value,
                    "request_id": ctx.request_id,
                    "event": "skipped",
                    "reason": "no static payloads for family",
                    "family": self._cfg.kb_static_family,
                }
            )
            return []
        cands = [
            PayloadCandidate(
                value=p,
                source_label="kb_static",
                experiment_group=ExperimentGroup.STATIC_DATASET.value,
            )
            for p in payloads
        ]
        out = self._cfg.outcome_provider(ExperimentGroup.STATIC_DATASET, ctx, cands)
        trials = self._materialize(
            group=ExperimentGroup.STATIC_DATASET,
            ctx=ctx,
            candidates=cands,
            outcomes=out,
            log_tag="B",
        )
        self._log(
            {
                "arm": ExperimentGroup.STATIC_DATASET.value,
                "request_id": ctx.request_id,
                "event": "completed",
                "trial_count": len(trials),
                "kb_static_family": self._cfg.kb_static_family,
            }
        )
        return trials

    def _run_arm_c(self, ctx: RequestContext) -> list[TrialRecord]:
        opts = self._gen_options_base()
        req = GenerationRequest(
            context=ctx,
            family=self._cfg.generation_family,
            k_seeds=self._cfg.k_seeds,
            n_candidates=self._cfg.n_candidates,
            lab_run_id=f"arm_C_{ctx.request_id}",
            options=opts,
        )
        ranked = self._cfg.generation_pipeline.run(req)
        if not ranked:
            self._log(
                {
                    "arm": ExperimentGroup.GENERATED.value,
                    "request_id": ctx.request_id,
                    "event": "skipped",
                    "reason": "pipeline returned no candidates",
                }
            )
            return []
        cands = [g.to_payload_candidate(source_label="generative") for g in ranked]
        out = self._cfg.outcome_provider(ExperimentGroup.GENERATED, ctx, cands)
        trials = self._materialize(
            group=ExperimentGroup.GENERATED,
            ctx=ctx,
            candidates=cands,
            outcomes=out,
            log_tag="C",
        )
        self._log(
            {
                "arm": ExperimentGroup.GENERATED.value,
                "request_id": ctx.request_id,
                "event": "completed",
                "trial_count": len(trials),
                "generation_family": self._cfg.generation_family,
                "n_candidates_requested": self._cfg.n_candidates,
            }
        )
        return trials

    def _run_arm_d(self, ctx: RequestContext) -> list[TrialRecord]:
        assert self._controller is not None
        all_trials: list[TrialRecord] = []
        for round_ix in range(self._cfg.d_rounds_per_context):
            decision = self._controller.select_strategy(ctx)
            gen_opts = {**self._gen_options_base(), **strategy_arm_to_generation_options(decision.arm)}
            gen_opts["random_seed"] = hash((ctx.request_id, round_ix, decision.arm.index)) % (2**32)
            # Distinct from arm C: no thesis_arm "C" identity-skip; label bandit context on outputs.
            gen_opts["thesis_arm"] = "D"
            gen_opts["adaptive_strategy_label"] = decision.arm.label
            gen_opts["adaptive_round"] = round_ix
            req = GenerationRequest(
                context=ctx,
                family=decision.arm.family,
                k_seeds=self._cfg.k_seeds,
                n_candidates=self._cfg.n_candidates,
                lab_run_id=f"arm_D_{ctx.request_id}_r{round_ix}",
                options=gen_opts,
            )
            ranked = self._cfg.generation_pipeline.run(req)
            if not ranked:
                self._log(
                    {
                        "arm": ExperimentGroup.GENERATED_ADAPTIVE.value,
                        "request_id": ctx.request_id,
                        "round": round_ix,
                        "event": "skipped",
                        "reason": "pipeline returned no candidates",
                        "chosen_arm": decision.arm.label,
                    }
                )
                continue
            for cand in ranked:
                cand.metadata["adaptive_strategy_arm"] = decision.arm.label
                cand.metadata["adaptive_round"] = int(round_ix)
                cand.metadata["thesis_arm"] = "D"
            top = ranked[0]
            pc = top.to_payload_candidate(source_label="generative_adaptive")
            outcomes = self._cfg.outcome_provider(ExperimentGroup.GENERATED_ADAPTIVE, ctx, [pc])
            trials = self._materialize(
                group=ExperimentGroup.GENERATED_ADAPTIVE,
                ctx=ctx,
                candidates=[pc],
                outcomes=outcomes,
                log_tag=f"D_r{round_ix}",
                round_index=round_ix,
                strategy_arm_label=decision.arm.label,
            )
            all_trials.extend(trials)
            metrics = _outcome_row_to_metrics(
                outcomes[0],
                baseline_status_code=self._cfg.baseline_status_code,
                baseline_response_length=self._cfg.baseline_response_length,
            )
            reward = self._controller.register_outcome(ctx, decision.arm, metrics)
            self._log(
                {
                    "arm": ExperimentGroup.GENERATED_ADAPTIVE.value,
                    "request_id": ctx.request_id,
                    "round": round_ix,
                    "event": "round_completed",
                    "chosen_arm": decision.arm.label,
                    "ucb_scores": list(decision.ucb_scores),
                    "reward": reward,
                    "trial_id": trials[0].trial_id if trials else None,
                }
            )
        return all_trials

    def run(self) -> ExperimentRunResult:
        """
        Execute configured arms for each context in order **A → B → C → D**.

        Bandit state for **D** persists across contexts and rounds within this call.
        """
        self._result = ExperimentRunResult()
        arm_order = (
            ExperimentGroup.BASELINE_BURP,
            ExperimentGroup.STATIC_DATASET,
            ExperimentGroup.GENERATED,
            ExperimentGroup.GENERATED_ADAPTIVE,
        )
        for ctx in self._cfg.contexts:
            self._log({"event": "context_start", "request_id": ctx.request_id})
            for arm in arm_order:
                if arm not in self._cfg.arms:
                    continue
                if arm == ExperimentGroup.BASELINE_BURP:
                    self._result.trial_records.extend(self._run_arm_a(ctx))
                elif arm == ExperimentGroup.STATIC_DATASET:
                    self._result.trial_records.extend(self._run_arm_b(ctx))
                elif arm == ExperimentGroup.GENERATED:
                    self._result.trial_records.extend(self._run_arm_c(ctx))
                elif arm == ExperimentGroup.GENERATED_ADAPTIVE:
                    self._result.trial_records.extend(self._run_arm_d(ctx))
            self._log({"event": "context_end", "request_id": ctx.request_id})
        self._log({"event": "run_complete", "total_trials": len(self._result.trial_records)})
        return self._result


def summarize_trial_records(trial_records: list[TrialRecord]) -> Any:
    """
    Per-arm comparison metrics from in-memory :class:`TrialRecord` rows.

    Delegates to :func:`evaluation_pipeline.comparison_metrics_table` (same math as
    thesis CSV aggregation). Returns a :class:`pandas.DataFrame`.
    """
    from .evaluation_pipeline import comparison_metrics_table

    return comparison_metrics_table(trial_records)
