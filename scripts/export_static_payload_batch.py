#!/usr/bin/env python3
"""
Export **raw** payloads from the enriched knowledge base for experiment arm **B**
(static dataset), without retrieval scoring or generative transforms.

This complements :mod:`scripts.generate_payload_batch` (arm **C**), which runs
:class:`src.payload_generator.PayloadGenerationPipeline`. Here, rows are taken
directly from ``payload`` so the thesis can contrast *dataset replay* vs
*retrieval-conditioned composition*.

Usage (repository root)::

    python scripts/export_static_payload_batch.py \\
        --kb data/enriched_payloads.csv \\
        --family xss \\
        --count 50 \\
        -o results/intruder_static_xss.txt

Deterministic mode (default): rows matching ``kb_family`` are sorted by ``row_id``
(numeric when possible, else lexicographic), then the first ``--count`` payloads
are written. With ``--random-seed``, a reproducible sample of ``--count`` distinct
rows is drawn instead.

Optional ``--csv-out`` writes ``row_id``, ``payload``, ``kb_family`` for the
audit trail.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

from _repo_root import ensure_repo_on_path

ensure_repo_on_path()

from src.payload_generator import sanitize_intruder_lines


def _normalize_family(s: str) -> str:
    return (s or "").strip().lower().replace(" ", "_")


def _row_id_key(row: dict[str, str]) -> tuple:
    rid = row.get("row_id") or row.get("rowid") or ""
    try:
        return (0, int(str(rid).strip()))
    except ValueError:
        return (1, str(rid))


def load_matching_rows(path: Path, family: str) -> list[dict[str, str]]:
    fam = _normalize_family(family)
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out: list[dict[str, str]] = []
    for r in rows:
        kb = _normalize_family(r.get("kb_family") or r.get("category") or "")
        if kb == fam:
            out.append(r)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export static KB payloads for arm B (Intruder-friendly).")
    p.add_argument("--kb", type=Path, required=True, help="Path to enriched_payloads.csv.")
    p.add_argument("--family", "-f", required=True, help="kb_family to filter (e.g. xss, sql).")
    p.add_argument("--count", "-n", type=int, default=50, help="Number of payloads to export (default: 50).")
    p.add_argument(
        "--random-seed",
        type=int,
        default=None,
        help="If set, sample this many rows with replacement disabled (reproducible).",
    )
    p.add_argument("--out", "-o", type=Path, required=True, help="Text file: one payload per line.")
    p.add_argument("--csv-out", type=Path, default=None, help="Optional audit CSV (row_id, payload, kb_family).")
    args = p.parse_args(argv)

    kb_path = Path(args.kb)
    if not kb_path.is_file():
        print(f"error: KB not found: {kb_path}", file=sys.stderr)
        return 2

    pool = load_matching_rows(kb_path, str(args.family))
    if not pool:
        print(f"error: no rows with kb_family matching {args.family!r}", file=sys.stderr)
        return 2

    n = min(int(args.count), len(pool))
    if args.random_seed is not None:
        rng = random.Random(int(args.random_seed))
        idx = list(range(len(pool)))
        rng.shuffle(idx)
        chosen = [pool[i] for i in idx[:n]]
    else:
        pool_sorted = sorted(pool, key=_row_id_key)
        chosen = pool_sorted[:n]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    raw_payloads = [(r.get("payload") or "").replace("\r\n", "\n").replace("\r", "\n") for r in chosen]
    lines = sanitize_intruder_lines(raw_payloads)
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    print(f"Wrote {len(lines)} payload(s) to {out_path}")

    if args.csv_out is not None:
        csv_path = Path(args.csv_out)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["row_id", "payload", "kb_family"])
            for r in chosen:
                w.writerow(
                    [
                        r.get("row_id") or r.get("rowid") or "",
                        r.get("payload") or "",
                        r.get("kb_family") or r.get("category") or "",
                    ]
                )
        print(f"Wrote audit CSV to {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
