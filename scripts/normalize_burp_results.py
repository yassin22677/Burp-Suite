#!/usr/bin/env python3
"""
Normalize **saved** Burp Suite Intruder result tables into the trial schema used by
:mod:`src.evaluation_pipeline` (``prepare_trial_dataframe`` / aggregation).

**Scope:** reads a file **you exported or copied** after a manual Intruder run. This
script does **not** connect to Burp, replay traffic, or control a scanner.

Reads exports via :func:`src.burp_bridge.read_burp_intruder_export` (tab/comma auto-detect).
See :mod:`src.burp_bridge` for the end-to-end six-step manual workflow.

Typical inputs (four arms, separate files)::

    baseline_results.csv
    static_payload_results.csv
    generated_payload_results.csv
    adaptive_generated_results.csv

Run this script **once per file** with the matching ``--group`` and the same
``--request-id`` / ``--baseline-*`` values when they describe one fuzzed context.

After normalizing arms **B** and **C**, compare outputs with
``python scripts/compare_normalized_trials.py trials_B_….csv trials_C_….csv`` to catch
accidental reuse of the same Intruder payload list.

Normalized output schema (one row per Intruder row)
----------------------------------------------------
Written as UTF-8 CSV with headers aligned to the evaluation pipeline:

- ``experiment_group`` — canonical arm label (``A_baseline_burp``, …).
- ``trial_id`` — ``{prefix}_{row_index}`` (see ``--trial-id-prefix``).
- ``request_id`` — stable id you pass on the CLI (pair trials across arms).
- ``baseline_status_code``, ``trial_status_code``,
  ``baseline_response_length``, ``trial_response_length`` — ints or empty.
- ``candidate_value`` — **full payload text** from the Burp column (no truncation).
- ``payload_sha256`` — short hash from ``prepare_trial_dataframe`` if missing.
- ``is_invalid_candidate`` — from export column if mapped, else false.
- ``is_abnormal`` — see **Abnormality rules** below.
- ``code_changed``, ``useful_signal`` — derived for metrics.

Tab-separated exports
---------------------
Burp often copies **tab-separated** tables. Use ``--sep tab`` or ``--sep auto``
(default): auto picks the separator with more occurrences in the first line
(tab vs comma).

Abnormality rules (transparent, configurable)
---------------------------------------------
After baseline broadcast and :func:`src.evaluation_pipeline.prepare_trial_dataframe`,
``is_abnormal`` is the logical **OR** of:

1. **Imported flag** — If you pass column overrides mapping ``is_abnormal`` to a
   Burp column, those true rows stay true.

2. **Status change** (on by default; disable with ``--no-abnormal-on-status-change``)::

     trial_status_code and baseline_status_code are both non-NaN and differ.

3. **Length delta** (on by default; disable with ``--no-abnormal-on-length-delta``)::

     trial_response_length and baseline_response_length are both non-NaN and
     abs(trial - baseline) > --length-delta-threshold

Finally ``useful_signal`` is recomputed as ``is_abnormal | code_changed`` so
:func:`src.evaluation_pipeline.aggregate_metrics_by_group` stays consistent.

Example usage
-------------

From repo root::

    python scripts/normalize_burp_results.py \\
        --input exports/baseline_results.tsv \\
        --output results/trials_A.csv \\
        --group A \\
        --request-id lab-search-json-01 \\
        --baseline-status 200 \\
        --baseline-length 3421 \\
        --sep tab

    python scripts/normalize_burp_results.py \\
        -i exports/generated_payload_results.csv \\
        -o results/trials_C.csv \\
        --group C \\
        --request-id lab-search-json-01 \\
        --baseline-status 200 \\
        --baseline-length 3421 \\
        --length-delta-threshold 250

Optional column overrides (Burp headers that do not match hints)::

    python scripts/normalize_burp_results.py -i raw.csv -o out.csv \\
        --group B --request-id r1 --baseline-status 200 --baseline-length 1000 \\
        --map-candidate \"Grep match\" \\
        --map-status \"Status code\" \\
        --map-length \"Resp. length\"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

# When this file is loaded via importlib (e.g. lab workbench), ``scripts/`` is not on
# ``sys.path``, so the sibling module ``_repo_root`` must be made importable first.
_scripts_dir = Path(__file__).resolve().parent
_scripts_dir_s = str(_scripts_dir)
if _scripts_dir_s not in sys.path:
    sys.path.insert(0, _scripts_dir_s)

from _repo_root import ensure_repo_on_path

REPO_ROOT = ensure_repo_on_path()

from src.burp_bridge import read_burp_intruder_export
from src.evaluation_pipeline import (
    COL_ABNORMAL,
    COL_BASELINE_LEN,
    COL_BASELINE_STATUS,
    COL_CODE_CHANGED,
    COL_TRIAL_LEN,
    COL_TRIAL_STATUS,
    COL_USEFUL,
    burp_intruder_to_prepared_dataframe,
    prepare_trial_dataframe,
)


def apply_abnormality_rules(
    prepared: pd.DataFrame,
    *,
    abnormal_on_status_change: bool,
    abnormal_on_length_delta: bool,
    length_delta_threshold: float,
) -> pd.DataFrame:
    """
    Set ``is_abnormal`` and refresh ``useful_signal`` using explicit CLI-driven rules.

    Preserves any ``is_abnormal`` already True from the source export (via
    ``burp_intruder_to_prepared_dataframe`` column mapping).
    """
    out = prepared.copy()
    bs = pd.to_numeric(out[COL_BASELINE_STATUS], errors="coerce")
    ts = pd.to_numeric(out[COL_TRIAL_STATUS], errors="coerce")
    bl = pd.to_numeric(out[COL_BASELINE_LEN], errors="coerce")
    tl = pd.to_numeric(out[COL_TRIAL_LEN], errors="coerce")

    inferred = pd.Series(False, index=out.index)
    if abnormal_on_status_change:
        inferred = inferred | (bs.notna() & ts.notna() & (bs != ts))
    if abnormal_on_length_delta:
        delta = (tl - bl).abs()
        inferred = inferred | (bl.notna() & tl.notna() & (delta > float(length_delta_threshold)))

    out[COL_ABNORMAL] = out[COL_ABNORMAL].astype(bool) | inferred
    out[COL_USEFUL] = out[COL_ABNORMAL] | out[COL_CODE_CHANGED].astype(bool)
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Normalize a saved Burp Intruder results file to evaluation_pipeline trial CSV "
            "(offline; no Burp connection)."
        ),
    )
    p.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to a Burp Intruder results table you saved manually (TSV/CSV).",
    )
    p.add_argument("--output", "-o", type=Path, required=True, help="Normalized trial CSV path.")
    p.add_argument(
        "--group",
        required=True,
        help="Experiment arm: A/B/C/D or full label (e.g. A_baseline_burp).",
    )
    p.add_argument("--request-id", required=True, help="Stable HTTP context id for all arms.")
    p.add_argument(
        "--baseline-status",
        type=int,
        required=True,
        help="Baseline HTTP status for this context (broadcast to every row).",
    )
    p.add_argument(
        "--baseline-length",
        type=int,
        required=True,
        help="Baseline response length for this context (broadcast to every row).",
    )
    p.add_argument(
        "--sep",
        choices=("auto", "tab", "comma"),
        default="auto",
        help="Field separator: auto (default), tab, or comma.",
    )
    p.add_argument(
        "--encoding",
        default="utf-8-sig",
        help="Text encoding (default utf-8-sig for Windows BOM).",
    )
    p.add_argument(
        "--trial-id-prefix",
        default="trial",
        help="trial_id = {prefix}_{row_index} (default: trial).",
    )
    p.add_argument(
        "--length-delta-threshold",
        type=float,
        default=100.0,
        metavar="N",
        help="Mark abnormal when abs(trial_len - baseline_len) > N (default: 100).",
    )
    p.add_argument(
        "--no-abnormal-on-status-change",
        action="store_true",
        help="Do not mark abnormal solely on status code change vs baseline.",
    )
    p.add_argument(
        "--no-abnormal-on-length-delta",
        action="store_true",
        help="Do not mark abnormal on length delta (status/import only).",
    )
    p.add_argument(
        "--map-candidate",
        metavar="COL",
        help="Override: Burp column name for candidate_value.",
    )
    p.add_argument(
        "--map-status",
        metavar="COL",
        help="Override: Burp column name for trial_status_code.",
    )
    p.add_argument(
        "--map-length",
        metavar="COL",
        help="Override: Burp column name for trial_response_length.",
    )
    p.add_argument(
        "--map-invalid",
        metavar="COL",
        help="Optional: Burp column for is_invalid_candidate.",
    )
    p.add_argument(
        "--map-abnormal",
        metavar="COL",
        help="Optional: Burp column merged into is_abnormal (OR with inferred rules).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    inp = Path(args.input)
    if not inp.is_file():
        print(f"error: input not found: {inp}", file=sys.stderr)
        return 2

    raw = read_burp_intruder_export(inp, sep=args.sep, encoding=args.encoding)

    overrides: dict[str, str] = {}
    if args.map_candidate:
        overrides["candidate_value"] = args.map_candidate
    if args.map_status:
        overrides["trial_status_code"] = args.map_status
    if args.map_length:
        overrides["trial_response_length"] = args.map_length
    if args.map_invalid:
        overrides["is_invalid_candidate"] = args.map_invalid
    if args.map_abnormal:
        overrides["is_abnormal"] = args.map_abnormal

    prepared = burp_intruder_to_prepared_dataframe(
        raw,
        experiment_group=args.group,
        request_id=str(args.request_id),
        baseline_status_code=int(args.baseline_status),
        baseline_response_length=int(args.baseline_length),
        trial_id_prefix=str(args.trial_id_prefix),
        column_overrides=overrides or None,
        infer_abnormal_from_response=False,
    )

    prepared = apply_abnormality_rules(
        prepared,
        abnormal_on_status_change=not args.no_abnormal_on_status_change,
        abnormal_on_length_delta=not args.no_abnormal_on_length_delta,
        length_delta_threshold=float(args.length_delta_threshold),
    )

    # ensure derived columns consistent if prepare_trial_dataframe ever changes
    prepared = prepare_trial_dataframe(prepared)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prepared.to_csv(out_path, index=False, encoding="utf-8")

    print(f"Wrote {len(prepared)} row(s) to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
