#!/usr/bin/env python3
"""
Compare two **normalized** trial CSVs (e.g. ``trials_B_*.csv`` vs ``trials_C_*.csv``).

Exits 0 always; prints JSON with:

- row counts
- SHA-256 of ``candidate_value`` column (joined with newlines)
- whether candidate columns are byte-identical
- set overlap rate on distinct candidate strings

Usage (repo root)::

    python scripts/compare_normalized_trials.py ui_workspace/results/trials_B_x.csv ui_workspace/results/trials_C_x.csv
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from _repo_root import ensure_repo_on_path

ensure_repo_on_path()

from workbench_helpers import normalize_trial_dataframe_columns, safe_read_csv


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compare normalized trial CSVs (candidate_value focus).")
    p.add_argument("left", type=Path)
    p.add_argument("right", type=Path)
    args = p.parse_args(argv)

    for label, path in ("left", args.left), ("right", args.right):
        if not path.is_file():
            print(json.dumps({"error": f"{label} not found: {path}"}))
            return 2

    df1, e1 = safe_read_csv(args.left)
    df2, e2 = safe_read_csv(args.right)
    if df1 is None or e1:
        print(json.dumps({"error": f"left read failed: {e1}"}))
        return 2
    if df2 is None or e2:
        print(json.dumps({"error": f"right read failed: {e2}"}))
        return 2

    a = normalize_trial_dataframe_columns(df1)
    b = normalize_trial_dataframe_columns(df2)
    col = "candidate_value"
    out: dict = {
        "left_file": str(args.left),
        "right_file": str(args.right),
        "left_rows": len(a.index),
        "right_rows": len(b.index),
    }
    if col not in a.columns or col not in b.columns:
        out["error"] = f"missing {col} column"
        print(json.dumps(out, indent=2))
        return 2

    s1 = "\n".join(a[col].astype(str).tolist())
    s2 = "\n".join(b[col].astype(str).tolist())
    h1 = hashlib.sha256(s1.encode("utf-8")).hexdigest()
    h2 = hashlib.sha256(s2.encode("utf-8")).hexdigest()
    set_a = set(a[col].astype(str))
    set_b = set(b[col].astype(str))
    den = max(len(set_a), len(set_b), 1)
    overlap = len(set_a & set_b) / den
    out["candidate_column_sha256_left"] = h1
    out["candidate_column_sha256_right"] = h2
    out["candidate_columns_identical"] = s1 == s2
    out["distinct_candidate_overlap_rate"] = overlap
    if h1 == h2 and s1 == s2:
        out["warning"] = "Candidate columns are identical — confirm you used different Intruder payload files for B vs C."
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
