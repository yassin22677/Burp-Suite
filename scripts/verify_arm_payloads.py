#!/usr/bin/env python3
"""
Print payload statistics and pairwise overlap for one or more arm payload ``.txt`` files
(e.g. ``*_armB_static.txt``, ``*_armC_generated.txt``).

For each file:

- line (payload) count
- distinct payload count
- SHA-256 of newline-joined lines
- first five payloads (truncated)

For each pair of files:

- overlap as |A∩B|/max(|A|,|B|) (same as :func:`src.lab_arms.set_overlap_rate`)
- Jaccard |A∩B|/|A∪B|

Usage (repo root)::

    python scripts/verify_arm_payloads.py ui_workspace/results/lab_ui_01_armB_static.txt ui_workspace/results/lab_ui_01_armC_generated.txt
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _repo_root import ensure_repo_on_path

ensure_repo_on_path()

from src.lab_arms import set_overlap_rate, sha256_payload_lines


def _load_lines(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify arm payload text files: counts, hash, overlap.")
    p.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="Payload .txt files (one payload per line).",
    )
    p.add_argument("--json", action="store_true", help="Emit single JSON object instead of text.")
    args = p.parse_args(argv)

    entries: list[dict] = []
    sets: list[set[str]] = []
    for path in args.paths:
        if not path.is_file():
            print(f"error: not a file: {path}", file=sys.stderr)
            return 2
        lines = _load_lines(path)
        uniq = set(lines)
        h = sha256_payload_lines(lines)
        entries.append(
            {
                "path": str(path),
                "payload_count": len(lines),
                "unique_payload_count": len(uniq),
                "payload_sha256": h,
                "first_5_payloads": [x[:200] for x in lines[:5]],
            }
        )
        sets.append(uniq)

    pairwise: list[dict] = []
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            sa, sb = sets[i], sets[j]
            union = sa | sb
            jaccard = len(sa & sb) / len(union) if union else 1.0
            pairwise.append(
                {
                    "left": str(args.paths[i]),
                    "right": str(args.paths[j]),
                    "overlap_max_denominator": set_overlap_rate(sa, sb),
                    "jaccard": jaccard,
                }
            )

    out = {"files": entries, "pairwise_overlap": pairwise}
    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    for e in entries:
        print(f"=== {e['path']} ===")
        print(f"  payload_count:         {e['payload_count']}")
        print(f"  unique_payload_count:  {e['unique_payload_count']}")
        print(f"  payload_sha256:        {e['payload_sha256']}")
        print("  first_5_payloads:")
        for k, pl in enumerate(e["first_5_payloads"], 1):
            print(f"    {k}. {pl!r}")
    print("=== pairwise ===")
    for pr in pairwise:
        print(
            f"  {Path(pr['left']).name} vs {Path(pr['right']).name}: "
            f"overlap_max_den={pr['overlap_max_denominator']:.4f}  jaccard={pr['jaccard']:.4f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
