"""
Tests for :mod:`src.experiment_runner`, plus offline adaptive bandit and scanner policy
checks that previously lived in separate files (one place for orchestration-related behavior).
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

from src.adaptive_controller import (
    AdaptiveBanditController,
    OutcomeMetrics,
    arms_from_grid,
)
from src.context_extractor import RequestContextExtractor
from src.evaluation import EvaluationPipeline, ExperimentGroup, TrialRecord
from src.execution_backend import (
    ExecutionBatch,
    OfflineReplayExecutionBackend,
    replay_outcomes_from_mapping_rows,
    resolve_execution_batch,
)
from src.experiment_runner import (
    ExperimentRunner,
    ExperimentRunnerConfig,
    load_static_payloads_from_enriched_kb,
    strategy_arm_to_generation_options,
    summarize_trial_records,
)
from src.payload_generator import (
    EnrichedCsvSeedRetriever,
    HybridCandidateGenerator,
    MultiFactorExplainableRanker,
    PayloadGenerationPipeline,
    PermissiveLabValidator,
)
from src.payload_validator import PayloadCandidate
from src.scanner_policy import (
    HeuristicScannerPolicySelector,
    RoundRobinScannerPolicySelector,
    SCAN_POLICY_PRESETS,
    ScannerPolicyDecision,
    ScannerPolicySignals,
    attach_decision_to_trial_tags,
    get_scan_policy_preset,
    list_scan_policy_preset_ids,
)

_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
_OUTCOMES_FIXTURE = _FIXTURE_DIR / "offline_replay_outcomes.json"


def _make_pipeline(kb_path, **kwargs):
    return PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(kb_path),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
        **kwargs,
    )


def test_load_static_payloads(enriched_kb_path):
    vals = load_static_payloads_from_enriched_kb(
        enriched_kb_path, "xss", limit=10, random_seed=None
    )
    assert len(vals) == 2
    assert any("script" in v.lower() for v in vals)


def test_strategy_arm_options():
    from src.adaptive_controller import StrategyArm

    arm = StrategyArm(0, "xss", "hybrid")
    o = strategy_arm_to_generation_options(arm)
    assert o["generator_mode"] == "hybrid"
    arm2 = StrategyArm(1, "sql", "template")
    assert strategy_arm_to_generation_options(arm2)["generator_mode"] == "template"


def test_runner_abcd_minimal(runner_ctx, enriched_kb_path):
    """One context through A/B/C/D with fixture outcomes."""

    def provider(group, ctx, candidates):
        return [
            {
                "trial_status_code": 200,
                "trial_response_length": 100 + i,
                "is_abnormal": False,
            }
            for i, _ in enumerate(candidates)
        ]

    cfg = ExperimentRunnerConfig(
        contexts=[runner_ctx],
        arms=frozenset(
            {
                ExperimentGroup.BASELINE_BURP,
                ExperimentGroup.STATIC_DATASET,
                ExperimentGroup.GENERATED,
                ExperimentGroup.GENERATED_ADAPTIVE,
            }
        ),
        enriched_kb_path=enriched_kb_path,
        generation_pipeline=_make_pipeline(enriched_kb_path),
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=provider,
        baseline_status_code=200,
        baseline_response_length=100,
        baseline_burp_payloads=["admin", "' OR 1=1--"],
        kb_static_family="xss",
        static_payload_limit=2,
        generation_family="xss",
        k_seeds=2,
        n_candidates=4,
        generation_random_seed=0,
        d_rounds_per_context=2,
        strategy_families=("xss",),
        strategy_modes=("hybrid", "template"),
    )
    result = ExperimentRunner(cfg).run()
    assert result.trial_records
    groups = {t.group for t in result.trial_records}
    assert ExperimentGroup.BASELINE_BURP in groups
    assert ExperimentGroup.STATIC_DATASET in groups
    assert ExperimentGroup.GENERATED in groups
    assert ExperimentGroup.GENERATED_ADAPTIVE in groups
    d_logs = [e for e in result.metadata_log if e.get("arm") == ExperimentGroup.GENERATED_ADAPTIVE.value]
    assert any(e.get("event") == "round_completed" for e in d_logs)


def test_arm_d_updates_controller_ucb(runner_ctx, enriched_kb_path):
    ctrl = AdaptiveBanditController(arms=arms_from_grid(("xss",), ("hybrid", "template")))

    before = ctrl.select_strategy(runner_ctx).ucb_scores

    def provider(group, ctx, candidates):
        return [{"trial_status_code": 500, "trial_response_length": 50, "is_abnormal": True} for _ in candidates]

    cfg = ExperimentRunnerConfig(
        contexts=[runner_ctx],
        arms=frozenset({ExperimentGroup.GENERATED_ADAPTIVE}),
        enriched_kb_path=enriched_kb_path,
        generation_pipeline=_make_pipeline(enriched_kb_path),
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=provider,
        baseline_status_code=200,
        baseline_response_length=100,
        adaptive_controller=ctrl,
        d_rounds_per_context=3,
        k_seeds=2,
        n_candidates=4,
        generation_family="xss",
        strategy_families=("xss",),
        strategy_modes=("hybrid", "template"),
    )
    ExperimentRunner(cfg).run()
    after = ctrl.select_strategy(runner_ctx).ucb_scores
    assert any(abs(a - b) > 1e-9 for a, b in zip(before, after))


def test_arm_c_records_generator_metadata(runner_ctx, enriched_kb_path):
    """Arm C produces trial records with explainable generative metadata (no LLM fields)."""
    pipe = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(enriched_kb_path),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )

    def provider(group, ctx, candidates):
        return [{"trial_status_code": 200, "trial_response_length": 50} for _ in candidates]

    cfg = ExperimentRunnerConfig(
        contexts=[runner_ctx],
        arms=frozenset({ExperimentGroup.GENERATED}),
        enriched_kb_path=enriched_kb_path,
        generation_pipeline=pipe,
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=provider,
        baseline_status_code=200,
        baseline_response_length=100,
        generation_family="xss",
        k_seeds=2,
        n_candidates=20,
    )
    result = ExperimentRunner(cfg).run()
    assert result.trial_records
    assert any(t.candidate.extra.get("explanation") for t in result.trial_records)


def test_summarize_trial_records_returns_metrics_table(runner_ctx, enriched_kb_path):
    cfg = ExperimentRunnerConfig(
        contexts=[runner_ctx],
        arms=frozenset({ExperimentGroup.BASELINE_BURP}),
        enriched_kb_path=enriched_kb_path,
        generation_pipeline=_make_pipeline(enriched_kb_path),
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=lambda g, c, cand: [{"trial_status_code": 200, "trial_response_length": 1} for _ in cand],
        baseline_burp_payloads=["x"],
    )
    result = ExperimentRunner(cfg).run()
    m = summarize_trial_records(result.trial_records)
    assert not m.empty
    assert "trial_count" in m.columns


def test_arm_a_skipped_when_no_baseline_payloads(runner_ctx, enriched_kb_path):
    def provider(g, c, cand):
        return [{"trial_status_code": 200, "trial_response_length": 1} for _ in cand]

    cfg = ExperimentRunnerConfig(
        contexts=[runner_ctx],
        arms=frozenset({ExperimentGroup.BASELINE_BURP}),
        enriched_kb_path=enriched_kb_path,
        generation_pipeline=_make_pipeline(enriched_kb_path),
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=provider,
        baseline_burp_payloads=(),
    )
    r = ExperimentRunner(cfg).run()
    assert r.trial_records == []
    assert any(e.get("event") == "skipped" for e in r.metadata_log)


# --- AdaptiveBanditController (unit-level; merged from test_adaptive_bandit.py)


def test_bandit_select_then_register_changes_future_scores() -> None:
    ctx = RequestContextExtractor().extract(
        {
            "request_id": "bandit_ctx",
            "method": "POST",
            "url": "https://lab/app",
            "content_type": "application/json",
            "parameters": [{"name": "id", "location": "json"}],
        }
    )
    arms = arms_from_grid(("sql", "xss"), ("hybrid",))
    ctrl = AdaptiveBanditController(arms=arms, lin_alpha=0.5, memory_decay=0.85)

    d0 = ctrl.select_strategy(ctx)
    assert d0.arm in arms
    assert len(d0.ucb_scores) == len(arms)
    prev = d0.ucb_scores

    reward_used = ctrl.register_outcome(
        ctx,
        d0.arm,
        OutcomeMetrics(strong_abnormal=True),
    )
    assert reward_used > 0

    d1 = ctrl.select_strategy(ctx)
    assert len(d1.ucb_scores) == len(arms)
    assert any(abs(a - b) > 1e-9 for a, b in zip(prev, d1.ucb_scores))


def test_bandit_register_invalid_batch_yields_negative_reward_memory() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x", "method": "GET"})
    arms = arms_from_grid(("cmd",), ("hybrid", "template"))
    ctrl = AdaptiveBanditController(arms=arms, tracked_families=("sql", "xss", "cmd", "encoded_attack", "other"))
    d = ctrl.select_strategy(ctx)
    r = ctrl.register_outcome(ctx, d.arm, OutcomeMetrics(invalid_candidate_batch=True))
    assert r < 0


# --- scanner_policy (merged from test_scanner_policy.py)


def test_preset_catalog_stable_ids() -> None:
    ids = list_scan_policy_preset_ids()
    assert "balanced_audit" in ids
    assert len(ids) == len(SCAN_POLICY_PRESETS)
    p = get_scan_policy_preset("passive_conservative")
    assert p.audit_depth.value == "passive_only"
    assert p.montoya_action_hint == 3


def test_heuristic_fp_reduction() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x", "method": "GET"})
    sel = HeuristicScannerPolicySelector(ScannerPolicySignals(prefer_fp_reduction=True))
    d = sel.select(ctx, experiment_group=ExperimentGroup.GENERATED)
    assert d.preset_id == "fp_reduction_strict"
    assert any(s.step == "rule_fp" for s in d.rationale)


def test_heuristic_429_throttle() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x", "method": "GET"})
    sel = HeuristicScannerPolicySelector(ScannerPolicySignals(recent_429_rate=0.5))
    d = sel.select(ctx, experiment_group=ExperimentGroup.BASELINE_BURP)
    assert d.preset_id == "throttle_passive"


def test_heuristic_active_suggestion_overrides_fp() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x", "method": "GET"})
    sel = HeuristicScannerPolicySelector(
        ScannerPolicySignals(
            prefer_fp_reduction=True,
            suggest_active_deep_scan=True,
        )
    )
    d = sel.select(ctx, experiment_group=ExperimentGroup.GENERATED_ADAPTIVE)
    assert d.preset_id == "active_thorough"


def test_round_robin_order() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x", "method": "GET"})
    sel = RoundRobinScannerPolicySelector(("balanced_audit", "passive_conservative"))
    a = sel.select(ctx, experiment_group=ExperimentGroup.GENERATED)
    b = sel.select(ctx, experiment_group=ExperimentGroup.GENERATED)
    c = sel.select(ctx, experiment_group=ExperimentGroup.GENERATED)
    assert a.preset_id == "balanced_audit"
    assert b.preset_id == "passive_conservative"
    assert c.preset_id == "balanced_audit"


def test_round_robin_invalid_preset_raises() -> None:
    with pytest.raises(KeyError):
        RoundRobinScannerPolicySelector(("no_such_preset",))


def test_attach_decision_to_trial_tags() -> None:
    d = ScannerPolicyDecision(
        preset_id="balanced_audit",
        rationale=(),
    )
    tags: dict = {}
    attach_decision_to_trial_tags(tags, d)
    assert tags["scanner_policy_preset_id"] == "balanced_audit"
    assert "scanner_policy_summary" in tags
    assert tags["scanner_policy_summary"]["audit_depth"] == "passive_and_light_active"


def test_experiment_runner_logs_and_tags_scanner_policy(runner_ctx, enriched_kb_path) -> None:
    """When a selector is configured, metadata_log and TrialRecord.tags receive the decision."""

    def provider(group, ctx, candidates):
        return [{"trial_status_code": 200, "trial_response_length": 50} for _ in candidates]

    sel = HeuristicScannerPolicySelector(ScannerPolicySignals(prefer_fp_reduction=True))
    pipeline = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(enriched_kb_path),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )
    cfg = ExperimentRunnerConfig(
        contexts=[runner_ctx],
        arms=frozenset({ExperimentGroup.STATIC_DATASET}),
        enriched_kb_path=enriched_kb_path,
        generation_pipeline=pipeline,
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=provider,
        kb_static_family="xss",
        static_payload_limit=1,
        scanner_policy_selector=sel,
    )
    result = ExperimentRunner(cfg).run()
    assert result.trial_records
    t0 = result.trial_records[0]
    assert t0.tags.get("scanner_policy_preset_id") == "fp_reduction_strict"
    policy_events = [e for e in result.metadata_log if e.get("event") == "scanner_policy_selected"]
    assert policy_events
    assert policy_events[0]["scanner_policy_preset_id"] == "fp_reduction_strict"


def test_scanner_policy_independent_of_payload_arm_metadata(runner_ctx) -> None:
    """Strategy arm label is passed through for logging only; heuristic ignores it by default."""
    sel = HeuristicScannerPolicySelector(ScannerPolicySignals())
    d = sel.select(
        runner_ctx,
        experiment_group=ExperimentGroup.GENERATED_ADAPTIVE,
        round_index=3,
        strategy_arm_label="xss:hybrid",
    )
    assert d.preset_id == "balanced_audit"
    assert d.context.get("strategy_arm_label") == "xss:hybrid"


# --- execution_backend + EvaluationPipeline (merged from test_execution_backend.py)


def test_offline_replay_produces_trial_records() -> None:
    ctx = RequestContextExtractor().extract(
        {"request_id": "exec_test_01", "url": "https://lab.example/api", "method": "POST"}
    )
    cands = [
        PayloadCandidate(value="p0", source_label="test"),
        PayloadCandidate(value="p1", source_label="test"),
    ]
    with _OUTCOMES_FIXTURE.open(encoding="utf-8") as f:
        outcomes = json.load(f)

    backend = OfflineReplayExecutionBackend()
    batch = ExecutionBatch(
        request_context=ctx,
        candidates=cands,
        group=ExperimentGroup.STATIC_DATASET,
        baseline_status_code=200,
        baseline_response_length=500,
        replay_outcomes=outcomes,
        trial_id_prefix="t",
    )
    rows = backend.execute_batch(batch)
    assert len(rows) == 2
    assert rows[0].trial_id == "t_0"
    assert rows[0].trial_status_code == 200
    assert rows[0].baseline_response_length == 500
    assert rows[1].trial_status_code == 500
    assert rows[1].tags.get("is_abnormal") is True
    assert "note" in rows[1].tags


def test_offline_replay_requires_matching_lengths() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x"})
    backend = OfflineReplayExecutionBackend()
    batch = ExecutionBatch(
        request_context=ctx,
        candidates=[PayloadCandidate(value="a", source_label="t")],
        group=ExperimentGroup.GENERATED,
        replay_outcomes=[{"trial_status_code": 200, "trial_response_length": 1}, {}],
    )
    with pytest.raises(ValueError, match="replay_outcomes length"):
        backend.execute_batch(batch)


def test_replay_outcomes_from_mapping_rows_aliases() -> None:
    raw = [{"status": 404, "length": 99}]
    norm = replay_outcomes_from_mapping_rows(raw)
    assert norm[0]["trial_status_code"] == 404
    assert norm[0]["trial_response_length"] == 99


def test_resolve_execution_batch_accepts_string_key() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x"})
    batch = ExecutionBatch(
        request_context=ctx,
        candidates=[PayloadCandidate(value="x", source_label="t")],
        group=ExperimentGroup.BASELINE_BURP,
        replay_outcomes=[{"trial_status_code": 200, "trial_response_length": 10}],
    )
    m = {ExperimentGroup.BASELINE_BURP.value: batch}
    assert resolve_execution_batch(m, ExperimentGroup.BASELINE_BURP) is batch


def test_evaluation_pipeline_run_group_with_backend() -> None:
    ctx = RequestContextExtractor().extract({"request_id": "rg_1", "url": "https://lab/y", "method": "GET"})
    cands = [PayloadCandidate(value="' OR 1=1--", source_label="gen")]
    outcomes = [{"trial_status_code": 200, "trial_response_length": 42}]
    batch = ExecutionBatch(
        request_context=ctx,
        candidates=cands,
        group=ExperimentGroup.GENERATED,
        baseline_status_code=200,
        baseline_response_length=40,
        replay_outcomes=outcomes,
    )
    pipe = EvaluationPipeline(
        config={
            "execution_backend": OfflineReplayExecutionBackend(),
            "execution_batches": {ExperimentGroup.GENERATED: batch},
        }
    )
    trials = pipe.run_group(ExperimentGroup.GENERATED)
    assert len(trials) == 1
    assert isinstance(trials[0], TrialRecord)
    summaries = pipe.summarize(trials)
    assert len(summaries) == 1


def test_run_group_without_backend_still_raises() -> None:
    pipe = EvaluationPipeline(config={})
    with pytest.raises(NotImplementedError):
        pipe.run_group(ExperimentGroup.STATIC_DATASET)


def test_run_groups_in_order_executes_configured_arms() -> None:
    ctx = RequestContextExtractor().extract({"request_id": "rgo", "url": "https://lab/x", "method": "GET"})
    backend = OfflineReplayExecutionBackend()
    batch_a = ExecutionBatch(
        request_context=ctx,
        candidates=[PayloadCandidate(value="a0", source_label="t")],
        group=ExperimentGroup.BASELINE_BURP,
        baseline_status_code=200,
        baseline_response_length=50,
        replay_outcomes=[{"trial_status_code": 200, "trial_response_length": 50}],
        trial_id_prefix="A",
    )
    batch_b = ExecutionBatch(
        request_context=ctx,
        candidates=[PayloadCandidate(value="b0", source_label="t")],
        group=ExperimentGroup.STATIC_DATASET,
        baseline_status_code=200,
        baseline_response_length=50,
        replay_outcomes=[{"trial_status_code": 404, "trial_response_length": 80}],
        trial_id_prefix="B",
    )
    pipe = EvaluationPipeline(
        config={
            "execution_backend": backend,
            "execution_batches": {
                ExperimentGroup.BASELINE_BURP: batch_a,
                ExperimentGroup.STATIC_DATASET: batch_b,
            },
        }
    )
    trials = pipe.run_groups_in_order(
        (ExperimentGroup.BASELINE_BURP, ExperimentGroup.STATIC_DATASET),
        append_to_config_trials=False,
    )
    assert len(trials) == 2
    assert trials[0].group == ExperimentGroup.BASELINE_BURP
    assert trials[1].trial_status_code == 404


def test_run_all_unchanged_with_trials_only() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/z"})
    tr = TrialRecord(
        trial_id="manual_0",
        group=ExperimentGroup.STATIC_DATASET,
        request_context=ctx,
        candidate=PayloadCandidate(value="x", source_label="m"),
        baseline_status_code=200,
        baseline_response_length=10,
        trial_status_code=200,
        trial_response_length=10,
    )
    pipe = EvaluationPipeline(config={"trials": [tr]})
    out = pipe.run_all()
    assert ExperimentGroup.STATIC_DATASET in out


# --- End-to-end lab harness (merged from test_end_to_end_lab_pipeline.py)


def test_experiment_runner_all_arms_produces_metrics_rows(enriched_kb_path) -> None:
    ctx = RequestContextExtractor().extract(
        {
            "request_id": "e2e_01",
            "method": "GET",
            "url": "https://lab.example/search?q=test",
            "parameters": [{"name": "q", "location": "query"}],
        }
    )
    kb = enriched_kb_path
    pipeline = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(kb),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )

    def outcomes(group, context, candidates):
        _ = group, context
        return [
            {"trial_status_code": 200, "trial_response_length": 120 + i, "is_abnormal": False}
            for i, _ in enumerate(candidates)
        ]

    cfg = ExperimentRunnerConfig(
        contexts=[ctx],
        arms=frozenset(e for e in ExperimentGroup),
        enriched_kb_path=kb,
        generation_pipeline=pipeline,
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=outcomes,
        baseline_status_code=200,
        baseline_response_length=100,
        baseline_burp_payloads=["a", "b"],
        kb_static_family="xss",
        static_payload_limit=2,
        generation_family="xss",
        k_seeds=2,
        n_candidates=4,
        d_rounds_per_context=2,
        strategy_families=("xss",),
        strategy_modes=("hybrid", "template"),
    )
    result = ExperimentRunner(cfg).run()
    assert len(result.trial_records) >= 4
    metrics = summarize_trial_records(result.trial_records)
    assert not metrics.empty
    assert "experiment_group" in metrics.columns
    assert "trial_count" in metrics.columns
    groups = set(metrics["experiment_group"].astype(str))
    assert ExperimentGroup.BASELINE_BURP.value in groups


def _load_run_lab_experiment_module(repo_root):
    scripts = str(repo_root / "scripts")
    inserted = scripts not in sys.path
    if inserted:
        sys.path.insert(0, scripts)
    try:
        path = repo_root / "scripts" / "run_lab_experiment.py"
        spec = importlib.util.spec_from_file_location("_run_lab_experiment_smoke", path)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if inserted and sys.path and sys.path[0] == scripts:
            sys.path.pop(0)


@pytest.mark.parametrize("extra", [(), ("--print-metrics",)])
def test_run_lab_experiment_cli_demo(repo_root, extra: tuple[str, ...]) -> None:
    mod = _load_run_lab_experiment_module(repo_root)
    argv = ["--demo", *extra]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = mod.main(argv)
    out = buf.getvalue()
    assert rc == 0, out
    assert "trials:" in out
    if "--print-metrics" in argv:
        assert "[" in out


def test_burp_bridge_to_metrics_path() -> None:
    from src.burp_bridge import (
        extract_request_context,
        intruder_export_to_prepared_trials,
        prepared_trials_to_trial_records,
        read_burp_intruder_export_text,
    )

    text = "Payload,Status,Length\nxssprobe,200,555\n"
    df = read_burp_intruder_export_text(text, sep="comma")
    prepared = intruder_export_to_prepared_trials(
        df,
        experiment_group="C",
        request_id="e2e_bridge",
        baseline_status_code=200,
        baseline_response_length=500,
    )
    ctx = extract_request_context({"request_id": "e2e_bridge", "url": "https://lab/x", "method": "GET"})
    trials = prepared_trials_to_trial_records(prepared, ctx)
    m = summarize_trial_records(trials)
    assert len(m) == 1
    assert int(m["trial_count"].iloc[0]) == 1
