#!/usr/bin/env python3
"""
Operator CLI for :mod:`src.burp_bridge` (safe, file-based Burp hand-offs).

Subcommands
-----------
template-context
    Write an example JSON file compatible with :class:`src.context_extractor.RequestContextExtractor`.

validate-context
    Load JSON, parse into :class:`src.context_extractor.RequestContext`, print a short summary.

**Normalize Intruder exports** — use ``scripts/normalize_burp_results.py`` (column overrides,
abnormality rules). **Generate Intruder payloads** — ``scripts/generate_payload_batch.py``.

This script does not connect to Burp.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from _repo_root import ensure_repo_on_path

REPO_ROOT = ensure_repo_on_path()

from src.burp_bridge import (
    extract_request_context,
    load_request_context_json,
    write_example_request_context_template,
)


def cmd_template(args: argparse.Namespace) -> int:
    out = Path(args.output)
    write_example_request_context_template(out)
    print(f"Wrote example context JSON to {out}")
    print("Edit request_id, url/method, and parameters to match your Intruder position.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    raw = load_request_context_json(path)
    ctx = extract_request_context(raw)
    summary = {
        "request_id": ctx.request_id,
        "method": ctx.method,
        "url": ctx.url,
        "path": ctx.path,
        "parameter_count": len(ctx.parameter_tags),
        "parameters": [
            {"name": t.name, "location": t.location.value} for t in ctx.parameter_tags
        ],
    }
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Offline file tools for request-context JSON (no Burp connection).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("template-context", help="Write example request context JSON.")
    t.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("data/examples/lab_request_context.example.json"),
        help="Output path (default: data/examples/lab_request_context.example.json)",
    )
    t.set_defaults(func=cmd_template)

    v = sub.add_parser("validate-context", help="Validate and summarize a context JSON file.")
    v.add_argument("path", type=Path, help="Path to JSON produced by you or template-context.")
    v.set_defaults(func=cmd_validate)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
