"""Tests for :mod:`src.lab_arms` (separate B vs C batch exports)."""

from __future__ import annotations

import io
import json

import pandas as pd

from src.context_extractor import RequestContextExtractor
from src.evaluation import ExperimentGroup
from src.evaluation_pipeline import prepare_trial_dataframe
from src.lab_arms import (
    export_baseline_payloads_for_arm_a,
    export_static_payloads_for_arm_b,
    generate_payloads_for_arm_c,
    generate_payloads_for_arm_d_ui_simulated,
    reward_seed_payloads_from_prepared_trials,
    set_overlap_rate,
    sha256_payload_lines,
)
from src.payload_generator import (
    EnrichedCsvSeedRetriever,
    HybridCandidateGenerator,
    MultiFactorExplainableRanker,
    PayloadGenerationPipeline,
    PermissiveLabValidator,
)


def test_set_overlap_rate() -> None:
    assert set_overlap_rate({"a", "b"}, {"a", "c"}) == 0.5
    assert set_overlap_rate(set(), set()) == 1.0


def test_arm_b_and_c_produce_different_payloads(tmp_path, lab_request_dict, enriched_kb_path) -> None:
    ctx = RequestContextExtractor().extract(lab_request_dict)
    pipe = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(enriched_kb_path),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )
    b_txt = tmp_path / "b.txt"
    b_audit = tmp_path / "b_audit.csv"
    b_dbg = tmp_path / "b.json"
    exp_b = export_static_payloads_for_arm_b(
        kb_path=enriched_kb_path,
        family="xss",
        count=5,
        txt_path=b_txt,
        audit_path=b_audit,
        debug_path=b_dbg,
    )
    c_txt = tmp_path / "c.txt"
    c_audit = tmp_path / "c_audit.csv"
    c_dbg = tmp_path / "c.json"
    exp_c = generate_payloads_for_arm_c(
        ctx=ctx,
        pipeline=pipe,
        kb_path=enriched_kb_path,
        family="xss",
        k_seeds=2,
        n_candidates=8,
        lab_run_id="test_arm_c",
        options={"random_seed": 0},
        txt_path=c_txt,
        audit_path=c_audit,
        debug_path=c_dbg,
        static_b_lines_for_overlap=exp_b.lines_preview,
    )
    b_lines = [x.strip() for x in b_txt.read_text(encoding="utf-8").splitlines() if x.strip()]
    c_lines = [x.strip() for x in c_txt.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert b_lines
    assert c_lines
    assert set_overlap_rate(set(b_lines), set(c_lines)) < 1.0, (
        "Arm C ranked outputs should not exactly match arm B raw KB lines (transforms required)."
    )


def test_export_baseline_arm_a_writes_three_files(tmp_path) -> None:
    txt = tmp_path / "a.txt"
    audit = tmp_path / "a_audit.csv"
    dbg = tmp_path / "a.json"
    exp = export_baseline_payloads_for_arm_a(txt_path=txt, audit_path=audit, debug_path=dbg)
    assert exp.line_count >= 1
    lines = [x.strip() for x in txt.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert lines[0] == "<script>alert(1)</script>"


def test_arm_d_falls_back_distinct_from_c_when_no_prior_trials(tmp_path, lab_request_dict, enriched_kb_path) -> None:
    """Without trials_C_*.csv, D XORs random_seed so outputs differ from C (same form defaults)."""
    ctx = RequestContextExtractor().extract(lab_request_dict)
    pipe = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(enriched_kb_path),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )
    c_txt = tmp_path / "c.txt"
    d_txt = tmp_path / "d.txt"
    generate_payloads_for_arm_c(
        ctx=ctx,
        pipeline=pipe,
        kb_path=enriched_kb_path,
        family="xss",
        k_seeds=2,
        n_candidates=8,
        lab_run_id="t_c",
        options={"random_seed": 0},
        txt_path=c_txt,
        audit_path=tmp_path / "c_audit.csv",
        debug_path=tmp_path / "c_dbg.json",
    )
    generate_payloads_for_arm_d_ui_simulated(
        ctx=ctx,
        pipeline=pipe,
        kb_path=enriched_kb_path,
        family="xss",
        k_seeds=2,
        n_candidates=8,
        lab_run_id="t_d",
        options={"random_seed": 0},
        txt_path=d_txt,
        audit_path=tmp_path / "d_audit.csv",
        debug_path=tmp_path / "d_dbg.json",
        prior_arm_c_trials_path=tmp_path / "trials_C_missing.csv",
    )
    c_lines = [x.strip() for x in c_txt.read_text(encoding="utf-8").splitlines() if x.strip()]
    d_lines = [x.strip() for x in d_txt.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert c_lines
    assert d_lines
    assert sha256_payload_lines(c_lines) != sha256_payload_lines(d_lines)


def test_arm_d_reads_prior_arm_c_trials_for_reward_seeds(tmp_path, lab_request_dict, enriched_kb_path) -> None:
    trials_csv = tmp_path / "trials_C_test_ctx_01.csv"
    trials_csv.write_text(
        "experiment_group,trial_id,request_id,baseline_status_code,trial_status_code,"
        "baseline_response_length,trial_response_length,candidate_value,is_abnormal,is_invalid_candidate\n"
        f"{ExperimentGroup.GENERATED.value},t0,test_ctx_01,200,500,100,100,SEED_CODECHANGE,False,False\n"
        f"{ExperimentGroup.GENERATED.value},t1,test_ctx_01,200,200,100,500,SEED_BIGLEN,False,False\n"
        f"{ExperimentGroup.GENERATED.value},t2,test_ctx_01,200,200,100,100,SEED_WEAK,False,False\n"
        f"{ExperimentGroup.GENERATED.value},t3,test_ctx_01,200,200,100,150,SEED_SMALLLEN,False,False\n",
        encoding="utf-8",
    )
    ctx = RequestContextExtractor().extract(lab_request_dict)
    pipe = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(enriched_kb_path),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )
    d_txt = tmp_path / "d.txt"
    dbg = tmp_path / "d_dbg.json"
    generate_payloads_for_arm_d_ui_simulated(
        ctx=ctx,
        pipeline=pipe,
        kb_path=enriched_kb_path,
        family="xss",
        k_seeds=2,
        n_candidates=8,
        lab_run_id="t_d",
        options={"random_seed": 0},
        txt_path=d_txt,
        audit_path=tmp_path / "d_audit.csv",
        debug_path=dbg,
        prior_arm_c_trials_path=trials_csv,
    )
    import json

    trace = json.loads(dbg.read_text(encoding="utf-8"))
    assert trace.get("ui_adaptive_mode") == "feedback_only_reward_seeds"
    seed_rows = trace.get("retrieved_seeds") or []
    assert any((s.get("seed_id") or "").startswith("reward_prior_") for s in seed_rows)
    assert trace.get("adaptive_prior_trials_diag", {}).get("distinct_high_reward_payloads_kept", 0) >= 1
    assert trace.get("adaptive_prior_trials_diag", {}).get("adaptive_selection_log")


def test_arm_d_row_order_fallback_when_reward_slice_has_no_candidates(
    tmp_path, lab_request_dict, enriched_kb_path
) -> None:
    """If the top-fraction slice has only empty candidates, D still uses non-empty rows from the file."""
    trials_csv = tmp_path / "trials_C_sparse.csv"
    trials_csv.write_text(
        "experiment_group,trial_id,request_id,baseline_status_code,trial_status_code,"
        "baseline_response_length,trial_response_length,candidate_value,is_abnormal,is_invalid_candidate\n"
        f"{ExperimentGroup.GENERATED.value},t0,test_ctx_01,200,500,100,100,,False,False\n"
        f"{ExperimentGroup.GENERATED.value},t1,test_ctx_01,200,500,100,100,,False,False\n"
        f"{ExperimentGroup.GENERATED.value},t2,test_ctx_01,200,200,100,100,ROWORDER_SEED,False,False\n",
        encoding="utf-8",
    )
    ctx = RequestContextExtractor().extract(lab_request_dict)
    pipe = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(enriched_kb_path),
        HybridCandidateGenerator(),
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )
    d_txt = tmp_path / "d.txt"
    dbg = tmp_path / "d_dbg.json"
    generate_payloads_for_arm_d_ui_simulated(
        ctx=ctx,
        pipeline=pipe,
        kb_path=enriched_kb_path,
        family="xss",
        k_seeds=2,
        n_candidates=8,
        lab_run_id="t_d_rowfallback",
        options={"random_seed": 0},
        txt_path=d_txt,
        audit_path=tmp_path / "d_audit.csv",
        debug_path=dbg,
        prior_arm_c_trials_path=trials_csv,
    )
    import json

    trace = json.loads(dbg.read_text(encoding="utf-8"))
    assert trace.get("adaptive_prior_trials_diag", {}).get("relaxed_row_order_seed_fallback") is True
    d_lines = [x.strip() for x in d_txt.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert d_lines
    assert any("ROWORDER_SEED" in ln for ln in d_lines)


def test_reward_seed_payloads_top_fraction_selects_high_rows() -> None:
    raw = pd.read_csv(
        io.StringIO(
            "experiment_group,trial_id,request_id,baseline_status_code,trial_status_code,"
            "baseline_response_length,trial_response_length,candidate_value,is_abnormal,is_invalid_candidate\n"
            f"{ExperimentGroup.GENERATED.value},t0,r,200,200,100,100,low,False,False\n"
            f"{ExperimentGroup.GENERATED.value},t1,r,200,500,100,100,high_code,False,False\n"
        )
    )
    prep = prepare_trial_dataframe(raw)
    payloads, diag = reward_seed_payloads_from_prepared_trials(prep, top_fraction=0.3, max_distinct_cap=5)
    assert "high_code" in payloads
    assert "low" not in payloads
    assert diag["top_slice_row_count"] >= 1
