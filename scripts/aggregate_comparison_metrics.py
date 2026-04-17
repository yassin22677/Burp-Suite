#!/usr/bin/env python3
"""
Build ``results/comparison_metrics.csv`` from normalized trial tables (one CSV per arm).

Use after the **manual** Burp loop: generate payloads in Python, run Intruder, export
results, run ``normalize_burp_results.py`` per arm, then this script. Purely offline.

Each input file should be produced by :mod:`scripts.normalize_burp_results` or any
table compatible with :func:`src.evaluation_pipeline.comparison_metrics_table`.

Usage::

    python scripts/aggregate_comparison_metrics.py results/trials_A.csv results/trials_B.csv results/trials_C.csv

    python scripts/aggregate_comparison_metrics.py results/trials_*.csv -o results/comparison_metrics.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from _repo_root import ensure_repo_on_path

REPO_ROOT = ensure_repo_on_path()

from src.evaluation_pipeline import run_full_comparison_and_save
from workbench_helpers import safe_read_csv


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Offline: merge normalized trial CSVs and write comparison metrics (one row per arm). "
            "Does not connect to Burp."
        ),
    )
    p.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Normalized trial CSV paths (e.g. results/trials_A.csv ...).",
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output path (default: results/comparison_metrics.csv under repo root).",
    )
    args = p.parse_args(argv)

    frames: list[pd.DataFrame] = []
    for path in args.inputs:
        if not path.is_file():
            print(f"error: file not found: {path}", file=sys.stderr)
            return 2
        df, err = safe_read_csv(path)
        if df is None or err:
            print(f"error: could not read {path}: {err or 'unknown'}", file=sys.stderr)
            return 2
        frames.append(df)

    if not frames:
        print("error: no inputs", file=sys.stderr)
        return 2

    _, out_path = run_full_comparison_and_save(frames, output_path=args.output, repo_root=REPO_ROOT)
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
