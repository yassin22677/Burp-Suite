"""
Trial tables and metrics (:mod:`src.evaluation_pipeline`) plus Burp Intruder string/file
helpers (:mod:`src.burp_bridge`) — merged for one place to edit normalization tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from src.burp_bridge import (
    detect_intruder_separator,
    extract_request_context,
    intruder_export_to_prepared_trials,
    load_request_context_json,
    parse_intruder_table_text,
    prepared_trial_row_to_replay_outcome,
    prepared_trials_to_outcome_rows,
    prepared_trials_to_trial_records,
    read_burp_intruder_export,
    read_burp_intruder_export_text,
    request_context_to_json_dict,
    save_request_context_json,
    write_example_request_context_template,
)
from src.context_extractor import ParameterLocation
from src.evaluation import ExperimentGroup
from src.evaluation_pipeline import (
    COL_CANDIDATE,
    COL_GROUP,
    COL_TRIAL_ID,
    COL_TRIAL_LEN,
    COL_TRIAL_STATUS,
    aggregate_metrics_by_group,
    burp_intruder_to_prepared_dataframe,
    comparison_metrics_table,
    concat_prepared_trial_frames,
    prepare_trial_dataframe,
)


def test_prepare_trial_dataframe_adds_derived_columns() -> None:
    df = pd.DataFrame(
        {
            "experiment_group": [ExperimentGroup.STATIC_DATASET.value],
            "trial_id": ["t0"],
            "request_id": ["r1"],
            "baseline_status_code": [200],
            "trial_status_code": [500],
            "baseline_response_length": [100],
            "trial_response_length": [100],
            "candidate_value": ["' OR 1=1--"],
            "is_abnormal": [False],
            "is_invalid_candidate": [False],
        }
    )
    out = prepare_trial_dataframe(df)
    assert bool(out["code_changed"].iloc[0]) is True
    assert bool(out["useful_signal"].iloc[0]) is True
    assert out["payload_sha256"].iloc[0]


def test_burp_intruder_normalization_and_infer_abnormal() -> None:
    raw = pd.DataFrame(
        {
            "Payload": ["p1", "p2"],
            "Status": [200, 404],
            "Length": [100, 100],
        }
    )
    prep = burp_intruder_to_prepared_dataframe(
        raw,
        experiment_group="B",
        request_id="req_lab_1",
        baseline_status_code=200,
        baseline_response_length=100,
        infer_abnormal_from_response=True,
        abnormal_length_delta_threshold=0,
    )
    assert prep["experiment_group"].iloc[0] == ExperimentGroup.STATIC_DATASET.value
    assert prep["candidate_value"].tolist() == ["p1", "p2"]
    # status change or any length delta > 0 with threshold 0
    assert prep["is_abnormal"].any()


def test_aggregate_metrics_two_arms() -> None:
    a = burp_intruder_to_prepared_dataframe(
        pd.DataFrame({"Payload": ["x"], "Status": [200], "Length": [10]}),
        experiment_group="A",
        request_id="r",
        baseline_status_code=200,
        baseline_response_length=10,
        infer_abnormal_from_response=False,
    )
    b = burp_intruder_to_prepared_dataframe(
        pd.DataFrame({"Payload": ["y"], "Status": [500], "Length": [10]}),
        experiment_group="C",
        request_id="r",
        baseline_status_code=200,
        baseline_response_length=10,
        infer_abnormal_from_response=True,
        abnormal_length_delta_threshold=100,
    )
    combined = concat_prepared_trial_frames([a, b])
    metrics = aggregate_metrics_by_group(combined)
    assert len(metrics) == 2
    assert "trial_count" in metrics.columns
    assert "response_code_change_rate" in metrics.columns
    assert "signal_efficiency" in metrics.columns
    # C arm: 100% status change, zero length delta vs baseline → half weight on rate only.
    row_c = metrics.loc[metrics["experiment_group"] == ExperimentGroup.GENERATED.value].iloc[0]
    row_a = metrics.loc[metrics["experiment_group"] == ExperimentGroup.BASELINE_BURP.value].iloc[0]
    assert float(row_c["signal_efficiency"]) == 0.5
    assert float(row_a["signal_efficiency"]) == 0.0


def test_comparison_metrics_table_matches_aggregate() -> None:
    df = pd.DataFrame(
        {
            "experiment_group": [ExperimentGroup.GENERATED.value, ExperimentGroup.GENERATED.value],
            "trial_id": ["a", "b"],
            "request_id": ["r", "r"],
            "baseline_status_code": [200, 200],
            "trial_status_code": [200, 200],
            "baseline_response_length": [50, 50],
            "trial_response_length": [200, 50],
            "candidate_value": ["c1", "c2"],
            "is_abnormal": [True, False],
            "is_invalid_candidate": [False, False],
        }
    )
    prep = prepare_trial_dataframe(df)
    via_fn = comparison_metrics_table(prep)
    via_agg = aggregate_metrics_by_group(prep)
    assert len(via_fn) == len(via_agg)
    assert via_fn["trial_count"].iloc[0] == 2


# --- burp_bridge


def test_detect_intruder_separator() -> None:
    assert detect_intruder_separator("Payload\tStatus\tLength") == "\t"
    assert detect_intruder_separator("Payload,Status,Length") == ","


def test_read_burp_intruder_export_text_tsv() -> None:
    text = "Payload\tStatus\tLength\n<script>x</script>\t500\t1200\n"
    df = read_burp_intruder_export_text(text, sep="auto")
    assert len(df) == 1
    assert "<script" in str(df.iloc[0, 0])


def test_parse_intruder_strips_leading_blanks_and_sep_hint() -> None:
    text = "\n\nsep=,\nPayload\tStatus\tLength\nx\t200\t1\n"
    df = parse_intruder_table_text(text, sep="auto")
    assert len(df) == 1
    assert df.shape[1] == 3


def test_parse_intruder_loose_tsv_extra_splits() -> None:
    text = "Payload\tStatus\tLength\na\tb\textra\t500\t1200\n"
    df = parse_intruder_table_text(text, sep="auto")
    assert len(df) == 1
    assert df.shape[1] >= 3


def test_read_burp_intruder_export_utf16_le_file(tmp_path: Path) -> None:
    p = tmp_path / "intruder.txt"
    inner = "Payload\tStatus\tLength\np\t200\t10\n"
    p.write_bytes(b"\xff\xfe" + inner.encode("utf-16-le"))
    df = read_burp_intruder_export(p, sep="auto")
    assert len(df) == 1
    assert df.shape[1] == 3


def test_request_context_json_roundtrip(tmp_path: Path) -> None:
    raw = {
        "request_id": "rt_1",
        "method": "get",
        "url": "https://lab.example/items?q=1",
        "parameters": [{"name": "q", "location": "query", "declared_type": "string"}],
    }
    p = tmp_path / "ctx.json"
    save_request_context_json(p, raw)
    loaded = load_request_context_json(p)
    ctx = extract_request_context(loaded)
    assert ctx.request_id == "rt_1"
    assert ctx.method == "GET"
    assert ctx.parameter_tags[0].location == ParameterLocation.QUERY
    back = request_context_to_json_dict(ctx)
    ctx2 = extract_request_context(back)
    assert ctx2.request_id == ctx.request_id
    assert ctx2.url == ctx.url


def test_write_example_template(tmp_path: Path) -> None:
    out = tmp_path / "t.json"
    write_example_request_context_template(out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "request_id" in data
    extract_request_context(data)


def test_intruder_to_prepared_and_trial_records() -> None:
    text = "Payload,Status,Length\n' OR 1=1--,200,999\n"
    df = read_burp_intruder_export_text(text, sep="comma")
    prepared = intruder_export_to_prepared_trials(
        df,
        experiment_group="B",
        request_id="ctx-01",
        baseline_status_code=200,
        baseline_response_length=1000,
    )
    assert prepared[COL_GROUP].iloc[0] == ExperimentGroup.STATIC_DATASET.value
    ctx = extract_request_context(
        {"request_id": "ctx-01", "method": "GET", "url": "https://lab/x"}
    )
    records = prepared_trials_to_trial_records(prepared, ctx)
    assert len(records) == 1
    assert records[0].trial_id == "trial_0"
    assert records[0].group == ExperimentGroup.STATIC_DATASET
    assert "' OR 1=1--" in records[0].candidate.value


def test_prepared_trial_row_to_replay_outcome() -> None:
    row = {
        COL_TRIAL_STATUS: 500,
        COL_TRIAL_LEN: 300,
        "is_abnormal": True,
        "is_invalid_candidate": False,
    }
    out = prepared_trial_row_to_replay_outcome(row)
    assert out["trial_status_code"] == 500
    assert out["trial_response_length"] == 300
    assert out["is_abnormal"] is True


def test_prepared_trials_to_outcome_rows_matches_row_count() -> None:
    prepared = pd.DataFrame(
        [
            {
                COL_GROUP: ExperimentGroup.GENERATED.value,
                COL_TRIAL_ID: "t0",
                "request_id": "r1",
                COL_CANDIDATE: "a",
                COL_TRIAL_STATUS: 200,
                COL_TRIAL_LEN: 10,
                "baseline_status_code": 200,
                "baseline_response_length": 10,
                "is_abnormal": False,
                "is_invalid_candidate": False,
            }
        ]
    )
    prepared = prepare_trial_dataframe(prepared)
    outs = prepared_trials_to_outcome_rows(prepared)
    assert len(outs) == 1
    assert outs[0]["trial_status_code"] == 200


def test_prepared_trials_to_trial_records_requires_columns() -> None:
    bad = pd.DataFrame({COL_GROUP: ["B_static_dataset"]})
    ctx = extract_request_context({"url": "https://x", "method": "GET"})
    with pytest.raises(KeyError):
        prepared_trials_to_trial_records(bad, ctx)
