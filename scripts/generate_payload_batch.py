#!/usr/bin/env python3
"""
Offline Intruder payload batch (arm **C** path): KB retrieval → hybrid transforms →
validate → rank via :class:`src.payload_generator.PayloadGenerationPipeline`.

No Burp API or network. Full CLI reference: ``python scripts/generate_payload_batch.py --help``.
Workflow: request JSON (``--context`` or ``--builtin-context``) → ``-o`` .txt (one payload
per line) → optional ``--csv-out`` audit → Burp manually → ``normalize_burp_results.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from _repo_root import ensure_repo_on_path

REPO_ROOT = ensure_repo_on_path()

from src.context_extractor import RequestContextExtractor
from src.payload_generator import (
    EnrichedCsvSeedRetriever,
    GenerationRequest,
    HybridCandidateGenerator,
    PayloadGenerationPipeline,
    PermissiveLabValidator,
    sanitize_intruder_lines,
    write_ranked_generative_audit_csv,
)
from src.payload_ranker import MultiFactorExplainableRanker


DEFAULT_KB = REPO_ROOT / "data" / "enriched_payloads.csv"
DEFAULT_TEXT_OUT = REPO_ROOT / "results" / "generated_payloads.txt"

# Minimal embedded context: fuzzable form field (lab-only narrative).
BUILTIN_LAB_REQUEST: dict[str, Any] = {
    "request_id": "lab_builtin_login_form_01",
    "method": "POST",
    "url": "https://lab.example.local/app/login",
    "content_type": "application/x-www-form-urlencoded",
    "parameters": [
        {
            "name": "username",
            "location": "body_form",
            "declared_type": "string",
            "encoding_notes": ["url_encoded"],
        },
        {
            "name": "password",
            "location": "body_form",
            "declared_type": "string",
            "encoding_notes": ["url_encoded"],
        },
    ],
    "raw_excerpt": "Builtin fixture for offline batch generation (not a real target).",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Offline: generate payloads from the enriched KB for manual paste into Burp Intruder. "
            "No Burp connection, HTTP traffic, or scanner control."
        ),
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--context",
        type=str,
        metavar="PATH",
        help="JSON file for RequestContextExtractor (see src.context_extractor).",
    )
    g.add_argument(
        "--builtin-context",
        action="store_true",
        help="Use embedded lab request JSON instead of --context.",
    )
    p.add_argument("--family", "-f", required=True, help="kb_family filter (e.g. xss, sql, cmd).")
    p.add_argument("--k-seeds", type=int, default=5, help="Number of seeds to retrieve (default: 5).")
    p.add_argument(
        "--n-candidates",
        type=int,
        default=12,
        help="Target composed candidates before validate/rank (default: 12).",
    )
    p.add_argument(
        "--kb",
        type=Path,
        default=DEFAULT_KB,
        help=f"Path to enriched_payloads.csv (default: {DEFAULT_KB}).",
    )
    p.add_argument(
        "--out",
        "-o",
        type=Path,
        default=DEFAULT_TEXT_OUT,
        help=f"Plain text: one payload per line (default: {DEFAULT_TEXT_OUT}).",
    )
    p.add_argument(
        "--csv-out",
        type=Path,
        default=None,
        help="Optional CSV with metadata and explanation trace.",
    )
    p.add_argument("--random-seed", type=int, default=None, help="Reproducible ordering seed.")
    p.add_argument("--lab-run-id", type=str, default=None, help="Optional run id for logs.")
    p.add_argument(
        "--permissive-validator",
        action="store_true",
        help="Accept all candidates for validation (lab smoke only).",
    )
    p.add_argument(
        "--max-payload-len",
        type=int,
        default=None,
        help="Max payload length passed to the generator (optional).",
    )
    return p.parse_args(argv)


def load_raw_context(args: argparse.Namespace) -> dict[str, Any]:
    if args.builtin_context:
        return dict(BUILTIN_LAB_REQUEST)
    path = Path(args.context)
    if not path.is_file():
        raise FileNotFoundError(f"Context JSON not found: {path}")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def build_pipeline(
    kb_path: Path,
    permissive: bool,
) -> PayloadGenerationPipeline:
    retriever = EnrichedCsvSeedRetriever(kb_path)
    generator = HybridCandidateGenerator()
    ranker = MultiFactorExplainableRanker()
    validator = PermissiveLabValidator() if permissive else None
    return PayloadGenerationPipeline(retriever, generator, ranker, validator=validator)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    kb_path = Path(args.kb)
    if not kb_path.is_file():
        print(f"error: enriched KB not found: {kb_path}", file=sys.stderr)
        return 2

    raw = load_raw_context(args)
    context = RequestContextExtractor().extract(raw)

    options: dict[str, Any] = {}
    if args.random_seed is not None:
        options["random_seed"] = int(args.random_seed)
    if args.max_payload_len is not None:
        options["max_payload_len"] = int(args.max_payload_len)

    request = GenerationRequest(
        context=context,
        family=str(args.family),
        k_seeds=int(args.k_seeds),
        n_candidates=int(args.n_candidates),
        lab_run_id=args.lab_run_id,
        options=options,
    )

    pipeline = build_pipeline(
        kb_path,
        permissive=bool(args.permissive_validator),
    )
    ranked = pipeline.run(request)

    out_txt = Path(args.out)
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    safe_lines = sanitize_intruder_lines([c.value for c in ranked])
    out_txt.write_text("\n".join(safe_lines) + ("\n" if safe_lines else ""), encoding="utf-8")

    print(f"Wrote {len(safe_lines)} payload(s) to {out_txt}")

    if args.csv_out is not None:
        csv_path = Path(args.csv_out)
        write_ranked_generative_audit_csv(csv_path, ranked)
        print(f"Wrote metadata CSV to {csv_path}")

    if not safe_lines:
        print(
            "warning: no candidates after retrieval / generation / validation — check family, KB path, or use --permissive-validator.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
