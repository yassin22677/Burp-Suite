#!/usr/bin/env python3
"""
Run arms **A–D** in-process with :class:`src.experiment_runner.ExperimentRunner`.

**Not the primary Burp workflow:** this CLI is an **offline thesis harness** with a
deterministic ``outcome_provider`` (no target HTTP, no Burp connection). For the
usual lab loop (generate payloads → Intruder → export → normalize), use
``scripts/generate_payload_batch.py`` and ``scripts/normalize_burp_results.py``.

Same code path as ``examples/experiment_runner_minimal.py``, with optional CSV outputs.
Payload generation uses the offline hybrid pipeline only (see ``src/payload_generator``).
Replace the outcome provider in your own script when replaying rows derived from saved
Burp exports.

**Related tools (manual Burp path):** ``scripts/generate_payload_batch.py``,
``scripts/normalize_burp_results.py``, ``scripts/burp_bridge.py`` — see
:mod:`src.burp_bridge`.

Examples::

    # Tiny built-in KB + synthetic context (no data files required)
    python scripts/run_lab_experiment.py --demo --print-metrics

    # Your enriched CSV + context JSON
    python scripts/run_lab_experiment.py --context exports/lab.json --kb data/enriched_payloads.csv \\
        --trials-csv results/trials_run.csv --metrics-csv results/comparison_metrics.csv
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from _repo_root import ensure_repo_on_path

REPO_ROOT = ensure_repo_on_path()

from src.context_extractor import RequestContextExtractor
from src.evaluation import ExperimentGroup
from src.evaluation_pipeline import save_comparison_metrics, trial_records_to_dataframe
from src.execution_backend import OfflineReplayExecutionBackend
from src.experiment_runner import ExperimentRunner, ExperimentRunnerConfig, summarize_trial_records
from src.payload_generator import (
    EnrichedCsvSeedRetriever,
    HybridCandidateGenerator,
    MultiFactorExplainableRanker,
    PayloadGenerationPipeline,
    PermissiveLabValidator,
)

_DEMO_KB = """row_id,payload,kb_family,category,label_consistency_flag,heuristic_pattern_band,encoding_surface_class,percent_encoding_density,char_len_computed,length
0,<b>xss</b>,xss,xss,pattern_supports_family,script_tag_evidence,ascii_plain,0,10,10
1,plain,xss,xss,no_keyword_pattern_matched,unknown,ascii_plain,0,5,5
"""


def _parse_arms(raw: str) -> frozenset[ExperimentGroup]:
    mapping = {
        "A": ExperimentGroup.BASELINE_BURP,
        "B": ExperimentGroup.STATIC_DATASET,
        "C": ExperimentGroup.GENERATED,
        "D": ExperimentGroup.GENERATED_ADAPTIVE,
    }
    parts = [p.strip().upper() for p in raw.replace(",", " ").split() if p.strip()]
    if not parts:
        return frozenset(ExperimentGroup)
    out: set[ExperimentGroup] = set()
    for p in parts:
        if p not in mapping:
            raise argparse.ArgumentTypeError(f"Unknown arm {p!r}; use A, B, C, and/or D.")
        out.add(mapping[p])
    return frozenset(out)


def _builtin_context_dict() -> dict:
    return {
        "request_id": "cli_builtin_lab",
        "method": "POST",
        "url": "https://lab.example/api/items/search",
        "content_type": "application/json",
        "parameters": [
            {"name": "q", "location": "json", "declared_type": "string"},
        ],
    }


def _outcome_provider(group, ctx, candidates):
    """
    Deterministic offline replay **without** mirroring real HTTP.

    Important: outcomes must depend on **arm** and **payload** or B/C/D metrics collapse when
    trial counts match. (Ignoring ``group`` was a common source of “identical arm” tables.)
    """
    arm_tag = abs(hash(group.value)) % 997
    rid_tag = abs(hash(ctx.request_id)) % 251
    out: list[dict[str, Any]] = []
    for i, c in enumerate(candidates):
        pay_tag = abs(hash(c.value)) % 4093
        length = 100 + arm_tag + rid_tag + pay_tag % 200 + i * 7
        code = 200 if (pay_tag + arm_tag + i) % 17 != 0 else 500
        out.append(
            {
                "trial_status_code": code,
                "trial_response_length": length,
                "is_abnormal": code != 200,
            }
        )
    return out


def _run_experiment(kb_path: Path, ctx, args: argparse.Namespace) -> int:
    hybrid = HybridCandidateGenerator()
    pipeline = PayloadGenerationPipeline(
        EnrichedCsvSeedRetriever(kb_path),
        hybrid,
        MultiFactorExplainableRanker(),
        validator=PermissiveLabValidator(),
    )

    cfg = ExperimentRunnerConfig(
        contexts=[ctx],
        arms=args.arms,
        enriched_kb_path=kb_path,
        generation_pipeline=pipeline,
        execution_backend=OfflineReplayExecutionBackend(),
        outcome_provider=_outcome_provider,
        baseline_status_code=200,
        baseline_response_length=100,
        baseline_burp_payloads=["admin", "guest"],
        kb_static_family="xss",
        static_payload_limit=2,
        generation_family="xss",
        k_seeds=args.k_seeds,
        n_candidates=args.n_candidates,
        d_rounds_per_context=args.d_rounds,
        strategy_families=("xss",),
        strategy_modes=("hybrid", "template"),
    )
    result = ExperimentRunner(cfg).run()
    print(f"trials: {len(result.trial_records)}  metadata_log: {len(result.metadata_log)}")

    if args.trials_csv:
        args.trials_csv.parent.mkdir(parents=True, exist_ok=True)
        trial_records_to_dataframe(result.trial_records).to_csv(args.trials_csv, index=False)
        print(f"wrote trials: {args.trials_csv}")

    metrics = summarize_trial_records(result.trial_records)
    if args.metrics_csv:
        save_comparison_metrics(metrics, path=args.metrics_csv)
        print(f"wrote metrics: {args.metrics_csv}")
    if args.print_metrics:
        from src.evaluation_pipeline import metrics_to_json_records

        print(json.dumps(metrics_to_json_records(metrics), indent=2))

    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Offline thesis harness: ExperimentRunner arms A–D with fixture outcomes only. "
            "Does not connect to Burp; for manual Intruder workflow see generate_payload_batch.py."
        ),
    )
    p.add_argument("--demo", action="store_true", help="Use embedded mini KB + builtin context (ignores --kb if set).")
    p.add_argument("--context", type=Path, help="Path to RequestContext JSON (RequestContextExtractor schema).")
    p.add_argument("--builtin-context", action="store_true", help="Use embedded lab JSON context instead of --context.")
    p.add_argument(
        "--kb",
        type=Path,
        default=Path("data/enriched_payloads.csv"),
        help="Path to enriched_payloads.csv (default: data/enriched_payloads.csv; not used with --demo).",
    )
    p.add_argument(
        "--arms",
        type=_parse_arms,
        default=frozenset(ExperimentGroup),
        help="Subset e.g. 'A B C' or 'ABCD' (default: all).",
    )
    p.add_argument("--k-seeds", type=int, default=2)
    p.add_argument("--n-candidates", type=int, default=4)
    p.add_argument("--d-rounds", type=int, default=2, help="Bandit rounds per context (arm D).")
    p.add_argument("--trials-csv", type=Path, help="Write all TrialRecord rows to this CSV (trial schema).")
    p.add_argument("--metrics-csv", type=Path, help="Write comparison_metrics table to this path.")
    p.add_argument("--print-metrics", action="store_true", help="Print metrics JSON records to stdout.")
    args = p.parse_args(argv)

    if args.demo:
        with tempfile.TemporaryDirectory(prefix="lab_exp_") as td:
            kb_path = Path(td) / "enriched.csv"
            kb_path.write_text(_DEMO_KB, encoding="utf-8")
            ctx = RequestContextExtractor().extract(_builtin_context_dict())
            return _run_experiment(kb_path, ctx, args)

    if args.context and args.builtin_context:
        print("error: pass only one of --context or --builtin-context", file=sys.stderr)
        return 2
    if args.context:
        with args.context.open(encoding="utf-8") as f:
            ctx = RequestContextExtractor().extract(json.load(f))
    elif args.builtin_context:
        ctx = RequestContextExtractor().extract(_builtin_context_dict())
    else:
        print("error: use --demo, or --context PATH, or --builtin-context", file=sys.stderr)
        return 2

    kb_path = args.kb
    if not kb_path.is_file():
        print(f"error: KB not found: {kb_path}", file=sys.stderr)
        return 2

    return _run_experiment(kb_path, ctx, args)


if __name__ == "__main__":
    raise SystemExit(main())
