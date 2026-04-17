#!/usr/bin/env python3
"""
Standalone check: are experiment arms **B / C / (optional D)** accidentally identical?

Compares Intruder payload ``.txt`` files and normalized ``trials_*.csv`` files. Prints a human
report and the same data as JSON (use ``--json-only`` for JSON only).

Typical usage (repo root)::

    python scripts/verify_experiment_arms.py \\
        --b-payload ui_workspace/results/lab_01_armB_static.txt \\
        --c-payload ui_workspace/results/lab_01_armC_generated.txt \\
        --trials-b ui_workspace/results/trials_B_lab_01.csv \\
        --trials-c ui_workspace/results/trials_C_lab_01.csv

Optional arm D::

    python scripts/verify_experiment_arms.py \\
        --b-payload ... --c-payload ... --d-payload ... \\
        --trials-b ... --trials-c ... --trials-d ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from _repo_root import ensure_repo_on_path

ensure_repo_on_path()

import pandas as pd

from src.lab_arms import set_overlap_rate, sha256_payload_lines
from workbench_helpers import (
    hash_normalized_candidate_column,
    normalize_trial_dataframe_columns,
    read_validated_normalized_trial_csv,
)

LOUD = "\n" + "=" * 72 + "\n!!! WARNING — ARMS LOOK IDENTICAL OR METRICS AT RISK\n" + "=" * 72 + "\n"


def _load_payload_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _payload_file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_trial_fingerprint(df: pd.DataFrame, *, drop_group: bool) -> str:
    ndf = normalize_trial_dataframe_columns(df.copy())
    if drop_group and "experiment_group" in ndf.columns:
        ndf = ndf.drop(columns=["experiment_group"])
    cols = sorted(ndf.columns)
    ndf = ndf[cols].sort_values(by=list(cols)).reset_index(drop=True)
    blob = ndf.to_csv(index=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _build_payload_arm(
    label: str, path: Path | None
) -> dict[str, Any] | None:
    if path is None:
        return None
    if not path.is_file():
        return {
            "arm": label,
            "path": str(path),
            "error": "file not found",
        }
    lines = _load_payload_lines(path)
    uniq = set(lines)
    return {
        "arm": label,
        "path": str(path.resolve()),
        "payload_line_count": len(lines),
        "unique_payload_count": len(uniq),
        "payload_file_sha256": _payload_file_sha256(path),
        "payload_content_sha256": sha256_payload_lines(lines),
        "_set": uniq,
    }


def _strip_internal_keys(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if not k.startswith("_")}


def _build_trials_arm(label: str, path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if not path.is_file():
        return {
            "arm": label,
            "path": str(path),
            "error": "file not found",
        }
    df, err = read_validated_normalized_trial_csv(path)
    if df is None or err:
        return {
            "arm": label,
            "path": str(path.resolve()),
            "error": err or "could not read or invalid normalized trial CSV",
        }
    cand_hash = hash_normalized_candidate_column(df)
    fp_full = _canonical_trial_fingerprint(df, drop_group=False)
    fp_no_group = _canonical_trial_fingerprint(df, drop_group=True)
    return {
        "arm": label,
        "path": str(path.resolve()),
        "trial_row_count": len(df.index),
        "candidate_column_sha256": cand_hash,
        "trials_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_row_fingerprint_including_group": fp_full,
        "canonical_row_fingerprint_excluding_group": fp_no_group,
    }


def _pairwise_payload_overlap(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    valid = [(e["arm"], e.get("_set", set())) for e in entries if "error" not in e and "_set" in e]
    for i in range(len(valid)):
        for j in range(i + 1, len(valid)):
            a, sa = valid[i]
            b, sb = valid[j]
            union = sa | sb
            jaccard = len(sa & sb) / len(union) if union else 1.0
            out.append(
                {
                    "left": a,
                    "right": b,
                    "overlap_rate_max_denominator": set_overlap_rate(sa, sb),
                    "jaccard": jaccard,
                }
            )
    return out


def _pairwise_trial_checks(
    trials_entries: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Compare candidate hashes and row fingerprints; return detail rows + loud warning lines."""
    loud: list[str] = []
    details: list[dict[str, Any]] = []
    ok_t = [e for e in trials_entries if e and "error" not in e]
    for i in range(len(ok_t)):
        for j in range(i + 1, len(ok_t)):
            a, b = ok_t[i], ok_t[j]
            la, lb = a["arm"], b["arm"]
            cand_same = a["candidate_column_sha256"] == b["candidate_column_sha256"]
            row_same_full = a["canonical_row_fingerprint_including_group"] == b[
                "canonical_row_fingerprint_including_group"
            ]
            row_same_no_g = a["canonical_row_fingerprint_excluding_group"] == b[
                "canonical_row_fingerprint_excluding_group"
            ]
            entry = {
                "left": la,
                "right": lb,
                "candidate_value_columns_identical": cand_same,
                "normalized_rows_identical_including_experiment_group": row_same_full,
                "normalized_rows_identical_excluding_experiment_group": row_same_no_g,
            }
            details.append(entry)
            if cand_same:
                loud.append(
                    f"Arms {la} vs {lb}: **candidate_value column is byte-identical** "
                    "(same Intruder payload list normalized under two labels?)."
                )
            if row_same_full:
                loud.append(
                    f"Arms {la} vs {lb}: **full normalized trial tables match** including "
                    "`experiment_group` — files are duplicates."
                )
            elif row_same_no_g:
                loud.append(
                    f"Arms {la} vs {lb}: trial rows match **if you ignore experiment_group** — "
                    "same underlying Burp run, different arm label only."
                )
    return details, loud


def _metrics_invalid_reasons(
    payload_pairs: list[dict[str, Any]],
    trial_pairs: list[dict[str, Any]],
    payload_file_hashes: list[tuple[str, str]],
) -> list[str]:
    reasons: list[str] = []
    by_h: dict[str, list[str]] = defaultdict(list)
    for arm, h in payload_file_hashes:
        by_h[h].append(arm)
    for h, arms in by_h.items():
        if len(arms) > 1:
            reasons.append(
                f"Payload .txt files for arms {arms} are byte-identical (sha256 prefix {h[:16]}…)."
            )
    for p in payload_pairs:
        if p["overlap_rate_max_denominator"] >= 0.999 and p["jaccard"] >= 0.999:
            reasons.append(
                f"Payload files {p['left']} vs {p['right']}: ~identical sets "
                f"(overlap={p['overlap_rate_max_denominator']:.4f}, jaccard={p['jaccard']:.4f})."
            )
        elif p["overlap_rate_max_denominator"] >= 0.95:
            reasons.append(
                f"Payload files {p['left']} vs {p['right']}: very high overlap "
                f"({p['overlap_rate_max_denominator']:.4f}) — metrics may not distinguish arms."
            )
    for t in trial_pairs:
        if t["candidate_value_columns_identical"]:
            reasons.append(
                f"Trials {t['left']} vs {t['right']}: identical candidate_value column — "
                "comparison metrics over payloads are not independent."
            )
        if t["normalized_rows_identical_excluding_experiment_group"]:
            reasons.append(
                f"Trials {t['left']} vs {t['right']}: same rows aside from experiment_group — "
                "likely duplicate Burp export."
            )
    return reasons


def run_verify(args: argparse.Namespace) -> dict[str, Any]:
    b_txt = _build_payload_arm("B", args.b_payload)
    c_txt = _build_payload_arm("C", args.c_payload)
    d_txt = _build_payload_arm("D", args.d_payload)
    payload_raw = [b_txt, c_txt, d_txt]
    payload_entries = [x for x in payload_raw if x is not None]

    b_trials = _build_trials_arm("B", args.trials_b)
    c_trials = _build_trials_arm("C", args.trials_c)
    d_trials = _build_trials_arm("D", args.trials_d)
    trials_raw = [b_trials, c_trials, d_trials]
    trials_entries = [x for x in trials_raw if x is not None]

    payload_pairs = _pairwise_payload_overlap(payload_entries)
    trial_pairs, trial_loud = _pairwise_trial_checks(trials_entries)

    file_hashes = [
        (e["arm"], e["payload_file_sha256"])
        for e in payload_entries
        if "payload_file_sha256" in e
    ]
    metrics_reasons = _metrics_invalid_reasons(payload_pairs, trial_pairs, file_hashes)

    payload_loud: list[str] = []
    for p in payload_pairs:
        if p["overlap_rate_max_denominator"] >= 0.999 and p["jaccard"] >= 0.999:
            payload_loud.append(
                f"Payload arms {p['left']} vs {p['right']}: sets are effectively **identical** "
                f"(overlap={p['overlap_rate_max_denominator']:.4f}). "
                "Likely causes: same `*_armB_static.txt` and `*_armC_generated.txt` copied; "
                "arm C pipeline not used; or Intruder runs used the same paste buffer."
            )
        elif p["overlap_rate_max_denominator"] >= 0.95:
            payload_loud.append(
                f"Payload arms {p['left']} vs {p['right']}: **very high overlap**. "
                "Check Step 1 arm B vs C in the workbench and separate Intruder exports."
            )

    by_hash: dict[str, list[str]] = defaultdict(list)
    for arm, h in file_hashes:
        by_hash[h].append(arm)
    for h, arms in by_hash.items():
        if len(arms) > 1:
            payload_loud.append(
                f"Payload files for arms {arms} are **byte-identical** on disk "
                f"(sha256 prefix {h[:16]}…)."
            )

    all_loud = payload_loud + trial_loud
    causes_blurb = (
        "Likely causes summary: (1) Generated arm B and arm C from the same workbench mode; "
        "(2) Pasted the same payload file into Burp for multiple arms; "
        "(3) Normalized the same export twice with different group letters; "
        "(4) Arm D generated without a prior trials_C file so it only differs by RNG; "
        "or C/D payload files were copied."
    )

    report: dict[str, Any] = {
        "summary": {
            "arms_checked": [e["arm"] for e in payload_entries],
            "metrics_likely_invalid_due_to_duplicate_data": bool(metrics_reasons),
            "metrics_invalid_reasons": metrics_reasons,
            "loud_warnings": all_loud,
        },
        "payload_files": [_strip_internal_keys(e) for e in payload_entries],
        "payload_pairwise_overlap": payload_pairs,
        "trial_csv_files": trials_entries,
        "trial_pairwise_comparisons": trial_pairs,
        "notes": causes_blurb,
    }
    return report


def _print_human(report: dict[str, Any]) -> None:
    s = report["summary"]
    print("Experiment arm verification")
    print("-" * 72)
    print(f"Arms checked: {', '.join(s['arms_checked'])}")
    print()

    print("Payload files (.txt)")
    print("-" * 72)
    for e in report["payload_files"]:
        print(f"  Arm {e['arm']}: {e.get('path', '')}")
        if "error" in e:
            print(f"    ERROR: {e['error']}")
            continue
        print(f"    line_count={e['payload_line_count']}  unique={e['unique_payload_count']}")
        print(f"    file_sha256={e['payload_file_sha256']}")
        print(f"    content_sha256={e['payload_content_sha256']}")
    print()

    print("Payload set overlap (pairs)")
    print("-" * 72)
    for p in report["payload_pairwise_overlap"]:
        print(
            f"  {p['left']} vs {p['right']}: "
            f"overlap_max_den={p['overlap_rate_max_denominator']:.4f}  "
            f"jaccard={p['jaccard']:.4f}"
        )
    if not report["payload_pairwise_overlap"]:
        print("  (no pairs — need at least two payload files)")
    print()

    print("Normalized trial CSVs")
    print("-" * 72)
    for e in report["trial_csv_files"]:
        print(f"  Arm {e['arm']}: {e.get('path', '')}")
        if "error" in e:
            print(f"    ERROR: {e['error']}")
            continue
        print(f"    rows={e['trial_row_count']}")
        print(f"    candidate_column_sha256={e['candidate_column_sha256']}")
        print(f"    file_sha256={e['trials_file_sha256']}")
        print(f"    row_fp (with group)={e['canonical_row_fingerprint_including_group'][:24]}…")
        print(f"    row_fp (no group)   ={e['canonical_row_fingerprint_excluding_group'][:24]}…")
    print()

    print("Trial CSV pairwise checks")
    print("-" * 72)
    for t in report["trial_pairwise_comparisons"]:
        print(f"  {t['left']} vs {t['right']}:")
        print(f"    candidate columns identical: {t['candidate_value_columns_identical']}")
        print(f"    rows identical (incl. group): {t['normalized_rows_identical_including_experiment_group']}")
        print(f"    rows identical (excl. group): {t['normalized_rows_identical_excluding_experiment_group']}")
    if not report["trial_pairwise_comparisons"]:
        print("  (no pairs)")
    print()

    print("Metrics validity")
    print("-" * 72)
    if s["metrics_likely_invalid_due_to_duplicate_data"]:
        print("  **Metrics should NOT be trusted for independent arms.**")
        for r in s["metrics_invalid_reasons"]:
            print(f"    - {r}")
    else:
        print("  No duplicate-data red flags from these checks (still verify Burp methodology).")
    print()

    if s["loud_warnings"]:
        print(LOUD)
        for w in s["loud_warnings"]:
            print(w)
        print()
        print(report["notes"])
        print("=" * 72 + "\n")
    else:
        print("(No identical-arm loud warnings.)")
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Verify experiment arms B/C/(D): payload txt + trials CSV duplication checks.",
    )
    p.add_argument("--b-payload", type=Path, required=True, help="Arm B Intruder payload .txt")
    p.add_argument("--c-payload", type=Path, required=True, help="Arm C Intruder payload .txt")
    p.add_argument("--d-payload", type=Path, default=None, help="Optional arm D payload .txt")
    p.add_argument("--trials-b", type=Path, required=True, help="Normalized trials_B*.csv")
    p.add_argument("--trials-c", type=Path, required=True, help="Normalized trials_C*.csv")
    p.add_argument("--trials-d", type=Path, default=None, help="Optional trials_D*.csv")
    p.add_argument(
        "--json-only",
        action="store_true",
        help="Print only JSON (no human report).",
    )
    p.add_argument(
        "-o",
        "--json-out",
        type=Path,
        default=None,
        help="Also write JSON report to this path.",
    )
    args = p.parse_args(argv)

    report = run_verify(args)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json_only:
        print(json.dumps(report, indent=2))
        return 0

    _print_human(report)
    print("--- JSON ---")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
