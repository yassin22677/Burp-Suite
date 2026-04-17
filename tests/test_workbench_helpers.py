"""Tests for ``workbench_helpers`` and related Flask workbench helpers (CSV + metrics UI)."""

from __future__ import annotations

import csv
import importlib.util
import shutil
from pathlib import Path

import pandas as pd

from workbench_helpers import (
    AGGREGATE_INVALID_SELECTION_MSG,
    AGGREGATE_NO_SELECTION_MSG,
    NORMALIZED_TRIAL_SCHEMA_ERROR,
    build_aggregate_input_report,
    duplicate_payload_list_errors_vs_sibling_arms,
    filter_aggregate_selection_to_allowed,
    friendly_aggregate_rejection,
    hash_normalized_candidate_column,
    is_allowed_results_download,
    is_normalized_trial_dataframe,
    is_normalized_trials_output_filename,
    is_trials_aggregate_csv_filename,
    list_normalized_trial_csvs,
    load_trial_frames_for_aggregate,
    normalize_cross_arm_duplicate_warnings,
    paths_arm_payload_outputs,
    read_validated_normalized_trial_csv,
    safe_read_csv,
)


def _minimal_trial_row() -> dict[str, object]:
    return {
        "experiment_group": "A_baseline_burp",
        "trial_id": "trial_0",
        "request_id": "r1",
        "baseline_status_code": 200,
        "trial_status_code": 200,
        "baseline_response_length": 100,
        "trial_response_length": 100,
        "candidate_value": "x",
    }


def test_is_trials_aggregate_csv_filename() -> None:
    assert is_trials_aggregate_csv_filename("trials_A_lab.csv")
    assert is_trials_aggregate_csv_filename("TRIALS_b_x.CSV")
    assert is_trials_aggregate_csv_filename("trials_X_any.csv")
    assert is_trials_aggregate_csv_filename("trials_misc.csv")
    assert is_trials_aggregate_csv_filename("trials_a.csv")
    assert not is_trials_aggregate_csv_filename("comparison_metrics.csv")
    assert not is_trials_aggregate_csv_filename("burp_results.csv")
    assert not is_trials_aggregate_csv_filename("b1.csv")
    assert not is_trials_aggregate_csv_filename("trials_comparison_metrics.csv")
    assert not is_trials_aggregate_csv_filename("trials_burp_results.csv")
    assert not is_trials_aggregate_csv_filename("foo/trials_A.csv")
    assert not is_trials_aggregate_csv_filename("trials.txt")
    assert not is_trials_aggregate_csv_filename("results.csv")


def test_is_normalized_trials_output_filename() -> None:
    assert is_normalized_trials_output_filename("trials_A_lab.csv")
    assert is_normalized_trials_output_filename("trials_c_myid.csv")
    assert is_normalized_trials_output_filename("TRIALS_d_y.CSV")
    assert is_normalized_trials_output_filename("trials_B_x_y.csv")
    assert not is_normalized_trials_output_filename("trials_X_bad.csv")
    assert not is_normalized_trials_output_filename("trials_A.csv")
    assert not is_normalized_trials_output_filename("comparison_metrics.csv")
    assert not is_normalized_trials_output_filename("burp_raw.csv")
    assert not is_normalized_trials_output_filename("pretrials_x.csv")
    assert not is_normalized_trials_output_filename("trials.txt")


def test_safe_read_csv_utf8_and_cp1252(tmp_path) -> None:
    p = tmp_path / "u.csv"
    p.write_text("experiment_group,trial_id\nA,t1", encoding="utf-8-sig")
    df, err = safe_read_csv(p)
    assert err is None
    assert "experiment_group" in df.columns

    p2 = tmp_path / "w.csv"
    p2.write_bytes("a,b\n1,2".encode("cp1252"))
    df2, err2 = safe_read_csv(p2)
    assert err2 is None
    assert list(df2.columns) == ["a", "b"]


def test_is_normalized_trial_dataframe() -> None:
    ok, _ = is_normalized_trial_dataframe(pd.DataFrame([_minimal_trial_row()]))
    assert ok
    bad = pd.DataFrame([{"experiment_group": "A", "trial_id": "t"}])
    ok2, msg = is_normalized_trial_dataframe(bad)
    assert not ok2
    assert msg == NORMALIZED_TRIAL_SCHEMA_ERROR


def test_read_validated_normalized_trial_csv(tmp_path) -> None:
    p = tmp_path / "trials_B_r1.csv"
    pd.DataFrame([_minimal_trial_row() | {"experiment_group": "B_static_dataset"}]).to_csv(p, index=False)
    df, err = read_validated_normalized_trial_csv(p)
    assert err is None
    assert df is not None
    assert len(df) == 1

    p_space = tmp_path / "trials_A_spaced_headers.csv"
    row = _minimal_trial_row()
    with p_space.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([f"  {k}  " for k in row.keys()])
        w.writerow([row[k] for k in row.keys()])
    df3, err3 = read_validated_normalized_trial_csv(p_space)
    assert err3 is None
    assert df3 is not None
    assert "experiment_group" in df3.columns

    p2 = tmp_path / "trials_B_bad.csv"
    p2.write_text("not,csv,at,all\nx", encoding="utf-8")
    df2, err2 = read_validated_normalized_trial_csv(p2)
    assert df2 is None
    assert err2 == NORMALIZED_TRIAL_SCHEMA_ERROR


def test_list_normalized_trial_csvs_filters_schema(tmp_path) -> None:
    good = tmp_path / "trials_C_x.csv"
    pd.DataFrame([_minimal_trial_row() | {"experiment_group": "C_generated"}]).to_csv(good, index=False)
    bad = tmp_path / "trials_C_badmeta.csv"
    pd.DataFrame([{"experiment_group": "C", "trial_id": "1"}]).to_csv(bad, index=False)
    raw = tmp_path / "not_trials.csv"
    raw.write_text("a,b\n1,2", encoding="utf-8")
    junk = tmp_path / "trials_Z_random.csv"
    junk.write_text("a,b\n1,2", encoding="utf-8")

    names = list_normalized_trial_csvs(tmp_path)
    assert "trials_C_x.csv" in names
    assert "trials_C_badmeta.csv" not in names
    assert "not_trials.csv" not in names
    assert "trials_Z_random.csv" not in names


def test_list_normalized_hides_burp_named_csv(tmp_path) -> None:
    p = tmp_path / "burp_results.csv"
    pd.DataFrame([_minimal_trial_row()]).to_csv(p, index=False)
    assert list_normalized_trial_csvs(tmp_path) == []


def test_load_trial_frames_rejects_wrong_schema(tmp_path) -> None:
    p = tmp_path / "trials_A_x.csv"
    pd.DataFrame([{"foo": 1, "bar": 2}]).to_csv(p, index=False)
    frames, err, rep = load_trial_frames_for_aggregate(tmp_path, ["trials_A_x.csv"])
    assert frames is None
    assert err == AGGREGATE_INVALID_SELECTION_MSG
    assert rep is None


def test_load_trial_frames_empty_selection_message(tmp_path) -> None:
    frames, err, rep = load_trial_frames_for_aggregate(tmp_path, [])
    assert frames is None
    assert err == AGGREGATE_NO_SELECTION_MSG
    assert rep is None


def test_load_trial_frames_rejects_mixed_with_bad_name(tmp_path) -> None:
    good = tmp_path / "trials_A_ok.csv"
    pd.DataFrame([_minimal_trial_row()]).to_csv(good, index=False)
    frames, err, rep = load_trial_frames_for_aggregate(tmp_path, ["trials_A_ok.csv", "b1.csv"])
    assert frames is None
    assert err == AGGREGATE_INVALID_SELECTION_MSG
    assert rep is None


def test_load_trial_frames_accepts_cp1252_file(tmp_path) -> None:
    p = tmp_path / "trials_A_x.csv"
    pd.DataFrame([_minimal_trial_row()]).to_csv(p, index=False, encoding="cp1252")
    frames, err, rep = load_trial_frames_for_aggregate(tmp_path, ["trials_A_x.csv"])
    assert err is None
    assert frames is not None
    assert len(frames[0]) == 1
    assert rep is not None
    assert rep["per_file"]


def test_load_trial_frames_for_aggregate_success(tmp_path) -> None:
    p = tmp_path / "trials_A_r.csv"
    pd.DataFrame([_minimal_trial_row()]).to_csv(p, index=False)
    frames, err, rep = load_trial_frames_for_aggregate(tmp_path, ["trials_A_r.csv"])
    assert err is None
    assert frames is not None
    assert len(frames) == 1
    assert rep is not None


def test_normalize_cross_arm_duplicate_warnings(tmp_path) -> None:
    rid = "lab_same"
    row = _minimal_trial_row()
    b = tmp_path / f"trials_B_{rid}.csv"
    pd.DataFrame([row | {"experiment_group": "B_static_dataset"}]).to_csv(b, index=False)
    sha = hash_normalized_candidate_column(pd.read_csv(b))
    w = normalize_cross_arm_duplicate_warnings(tmp_path, rid, "C", sha)
    assert w
    assert any("arm B" in x or "trials_B" in x for x in w)


def test_aggregate_rejects_identical_file_bytes(tmp_path) -> None:
    p1 = tmp_path / "trials_A_first.csv"
    pd.DataFrame([_minimal_trial_row()]).to_csv(p1, index=False)
    p2 = tmp_path / "trials_A_second.csv"
    shutil.copyfile(p1, p2)
    frames, err, rep = load_trial_frames_for_aggregate(tmp_path, ["trials_A_first.csv", "trials_A_second.csv"])
    assert frames is None
    assert rep is None
    assert err is not None
    assert "identical" in err.lower() or "byte" in err.lower()


def test_build_aggregate_warns_same_candidates_different_groups(tmp_path) -> None:
    row = _minimal_trial_row()
    b = tmp_path / "trials_B_x.csv"
    c = tmp_path / "trials_C_x.csv"
    pd.DataFrame([row | {"experiment_group": "B_static_dataset"}]).to_csv(b, index=False)
    pd.DataFrame([row | {"experiment_group": "C_generated"}]).to_csv(c, index=False)
    df_b = pd.read_csv(b)
    df_c = pd.read_csv(c)
    rep = build_aggregate_input_report([b, c], [df_b, df_c])
    assert rep["warnings"]
    assert any("identical candidate_value" in w for w in rep["warnings"])


def test_friendly_aggregate_rejection_encoding_hint() -> None:
    s = friendly_aggregate_rejection("f.csv", "encoding failed")
    assert "encoding" in s.lower() or "format" in s.lower()


def test_filter_aggregate_selection_to_allowed() -> None:
    allowed = frozenset({"trials_A_x.csv", "trials_B_y.csv"})
    assert filter_aggregate_selection_to_allowed(
        [
            "trials_A_x.csv",
            "comparison_metrics.csv",
            "trials_A_x.csv",
            "../trials_B_y.csv",
            "trials_B_y.csv",
            "nope",
        ],
        allowed,
    ) == ["trials_A_x.csv", "trials_B_y.csv"]
    assert filter_aggregate_selection_to_allowed(["trials_B_y.csv", "trials_A_x.csv"], allowed) == [
        "trials_B_y.csv",
        "trials_A_x.csv",
    ]


def test_paths_arm_payload_outputs_a_and_d(tmp_path) -> None:
    r = tmp_path / "results"
    r.mkdir()
    a_txt, a_csv, a_json = paths_arm_payload_outputs(r, "rid1", "A")
    assert a_txt.name == "rid1_armA.txt"
    d_txt, d_csv, d_json = paths_arm_payload_outputs(r, "rid1", "D")
    assert d_txt.name == "rid1_armD.txt"
    assert d_csv.name == "rid1_armD_meta.csv"


def test_is_allowed_results_download_arm_a_d() -> None:
    assert is_allowed_results_download("x_armA.txt")
    assert is_allowed_results_download("x_armD_meta.csv")
    assert not is_allowed_results_download("x_armZ.txt")


def test_duplicate_payload_list_errors_vs_sibling_arms(tmp_path) -> None:
    r = tmp_path
    rid = "lab"
    b_txt, _, _ = paths_arm_payload_outputs(r, rid, "B")
    b_txt.parent.mkdir(parents=True, exist_ok=True)
    b_txt.write_text("one\ntwo\n", encoding="utf-8")
    err = duplicate_payload_list_errors_vs_sibling_arms(r, rid, "C", ["one", "two"])
    assert err and "arm B" in err[0]
    assert not duplicate_payload_list_errors_vs_sibling_arms(r, rid, "C", ["three", "four"])


# --- Flask app.py: aggregate summary text (merged from former test_app_metrics_summary.py)


def _import_root_workbench_app(repo_root: Path):
    path = repo_root / "app.py"
    spec = importlib.util.spec_from_file_location("workbench_flask_app", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_metrics_comparison_summary_explains_identical_outcome_rows(repo_root: Path) -> None:
    build_metrics_comparison_summary = _import_root_workbench_app(repo_root).build_metrics_comparison_summary

    metrics = pd.DataFrame(
        {
            "experiment_group": ["C_generated", "D_generated_adaptive"],
            "trial_count": [18, 18],
            "response_code_change_count": [16, 16],
            "response_code_change_rate": [0.89, 0.89],
            "avg_abs_length_delta": [4257.22, 4257.22],
            "unique_candidate_count": [18, 18],
            "signal_efficiency": [0.94, 0.94],
            "payload_column_fp": ["d689b7d4da68…", "3cb3869b09a9…"],
        }
    )
    text = build_metrics_comparison_summary(metrics)
    assert "not" in text.lower() and "bug" in text.lower()
    assert "highest" not in text.lower()
    assert "payload_column_fp" in text.lower()


def test_build_metrics_comparison_summary_picks_winner_when_rates_differ(repo_root: Path) -> None:
    build_metrics_comparison_summary = _import_root_workbench_app(repo_root).build_metrics_comparison_summary

    metrics = pd.DataFrame(
        {
            "experiment_group": ["C_generated", "D_generated_adaptive"],
            "trial_count": [10, 10],
            "response_code_change_count": [5, 8],
            "response_code_change_rate": [0.5, 0.8],
            "avg_abs_length_delta": [100.0, 50.0],
            "unique_candidate_count": [10, 10],
            "signal_efficiency": [0.4, 0.65],
        }
    )
    text = build_metrics_comparison_summary(metrics)
    assert "arm d" in text.lower() and "highest" in text.lower()


def test_workbench_metrics_main_table_keeps_subset_and_labels(repo_root: Path) -> None:
    mod = _import_root_workbench_app(repo_root)
    fn = mod._workbench_metrics_main_table
    metrics = pd.DataFrame(
        {
            "experiment_group": ["A_baseline_burp", "B_static_dataset"],
            "trial_count": [4, 12],
            "response_code_change_count": [0, 8],
            "response_code_change_rate": [0.0, 0.67],
            "abnormal_response_count": [4, 12],
            "abnormal_rate": [1.0, 1.0],
            "avg_abs_length_delta": [840.25, 1787.83],
            "useful_signal_count": [4, 12],
            "requests_per_useful_signal": [1.0, 1.0],
            "invalid_candidate_rate": [0.0, 0.0],
            "unique_candidate_count": [4, 12],
            "duplicate_candidate_rate": [0.0, 0.0],
            "signal_efficiency": [0.2, 0.75],
        }
    )
    out = fn(metrics)
    assert list(out.columns) == list(mod.WORKBENCH_METRICS_MAIN_COLUMNS)
    assert out["experiment_group"].tolist() == ["Arm A (baseline)", "Arm B (static KB)"]
    assert "response_code_change_count" not in out.columns
    assert "avg_abs_length_delta" not in out.columns
    assert "duplicate_candidate_rate" not in out.columns
