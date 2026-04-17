#!/usr/bin/env python3
"""
Offline educational demo: **group D** contextual bandit (LinUCB) for strategy selection.

This script does **not** send HTTP traffic, call Burp, or run the payload generator.
It only exercises :class:`src.adaptive_controller.AdaptiveBanditController` the same
way a future lab driver would: featurize :class:`src.context_extractor.RequestContext`,
pick a :class:`StrategyArm`, observe :class:`OutcomeMetrics`, update the bandit.

Demo flow (thesis narrative)
----------------------------
1. **Load context** — Built-in JSON fixture or ``--context`` file; parsed with
   :class:`src.context_extractor.RequestContextExtractor` into ``RequestContext``.
2. **Define arms** — :func:`arms_from_grid` builds a Cartesian grid of
   ``(family, generator_mode)`` (e.g. ``sql``/``xss``/``cmd`` × ``hybrid``/``template``).
   Each tuple is one discrete bandit arm (policy knob for downstream generation).
3. **Initialize controller** — ``AdaptiveBanditController`` wraps LinUCB (ridge design
   matrices per arm) and :class:`FamilyRewardMemory` (EMA of rewards per tracked family
   folded into the context vector).
4. **Interaction loop** (``--steps``) — Each round:
   a. ``select_strategy(ctx)`` → chosen arm + **full UCB score vector** (mean prediction
      + α·uncertainty; high score favors exploration early).
   b. A **fixture outcome** is applied (scripted sequence or named preset per step)
      as :class:`OutcomeMetrics` — mimicking what a harness would set after a replay.
   c. ``register_outcome(ctx, arm, outcome)`` → scalar reward via
      :func:`outcome_to_reward` / :class:`RewardPolicy`; LinUCB and family memory update.
   d. Print reward and a short running summary.
5. **Post-demo snapshot** — One extra ``select_strategy`` call prints **updated** UCB
   scores so readers see how estimates shift after feedback (still offline).

Example usage::

    python scripts/run_adaptive_selection_demo.py --builtin-context --steps 6

    python scripts/run_adaptive_selection_demo.py --context path/to/request.json --steps 8

    python scripts/run_adaptive_selection_demo.py --builtin-context --scenario random --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Sequence

from _repo_root import ensure_repo_on_path

ensure_repo_on_path()

from src.adaptive_controller import (
    AdaptiveBanditController,
    OutcomeMetrics,
    StrategyArm,
    arms_from_grid,
)
from src.context_extractor import RequestContextExtractor

# ---------------------------------------------------------------------------
# Request context (same pattern as generate_payload_batch.py)
# ---------------------------------------------------------------------------

BUILTIN_LAB_REQUEST: dict[str, Any] = {
    "request_id": "demo_adaptive_bandit_01",
    "method": "POST",
    "url": "https://lab.example.local/api/search",
    "content_type": "application/json",
    "parameters": [
        {"name": "q", "location": "json", "declared_type": "string"},
        {"name": "limit", "location": "json", "declared_type": "int"},
    ],
    "raw_excerpt": "Offline bandit demo — not a live target.",
}

# Named outcome fixtures (harness would set these after observing responses).
OUTCOME_PRESETS: dict[str, OutcomeMetrics] = {
    "none": OutcomeMetrics(
        baseline_status_code=200,
        trial_status_code=200,
        baseline_length=1200,
        trial_length=1195,
    ),
    "moderate": OutcomeMetrics(
        baseline_status_code=200,
        trial_status_code=200,
        baseline_length=1200,
        trial_length=2100,
        moderate_differential=True,
    ),
    "strong": OutcomeMetrics(
        baseline_status_code=200,
        trial_status_code=500,
        baseline_length=1200,
        trial_length=800,
        strong_abnormal=True,
    ),
    "invalid": OutcomeMetrics(
        invalid_candidate_batch=True,
    ),
}

# Default scripted story: mix of dull rounds, differential signal, and one strong hit.
DEFAULT_SCENARIO_SEQUENCE: tuple[str, ...] = (
    "none",
    "moderate",
    "none",
    "strong",
    "moderate",
    "none",
)


def load_raw_context(*, use_builtin: bool, context_path: str | None) -> dict[str, Any]:
    if use_builtin:
        return dict(BUILTIN_LAB_REQUEST)
    if not context_path:
        raise ValueError("context_path required when not using --builtin-context")
    path = Path(context_path)
    if not path.is_file():
        raise FileNotFoundError(f"Context JSON not found: {path}")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def format_ucb_line(arms: Sequence[StrategyArm], scores: tuple[float, ...]) -> str:
    parts = [f"{a.label}={s:.4f}" for a, s in zip(arms, scores)]
    return "  UCB: " + " | ".join(parts)


def outcome_from_preset(name: str) -> OutcomeMetrics:
    key = name.strip().lower()
    if key not in OUTCOME_PRESETS:
        choices = ", ".join(sorted(OUTCOME_PRESETS))
        raise ValueError(f"Unknown outcome preset {name!r}. Choose one of: {choices}")
    return OUTCOME_PRESETS[key]


def random_preset(rng: random.Random) -> str:
    return rng.choice(tuple(OUTCOME_PRESETS.keys()))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Offline LinUCB demo for experiment group D (strategy selection only).",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--context", type=str, metavar="PATH", help="JSON for RequestContextExtractor.")
    g.add_argument("--builtin-context", action="store_true", help="Use embedded lab request JSON.")
    p.add_argument("--steps", type=int, default=6, help="Number of select → register rounds (default: 6).")
    p.add_argument(
        "--scenario",
        choices=("scripted", "random"),
        default="scripted",
        help="scripted: default lesson sequence; random: draw outcome presets with --seed.",
    )
    p.add_argument("--seed", type=int, default=None, help="RNG seed for scenario=random.")
    p.add_argument(
        "--lin-alpha",
        type=float,
        default=0.8,
        help="LinUCB exploration strength (default: 0.8).",
    )
    p.add_argument(
        "--memory-decay",
        type=float,
        default=0.9,
        help="Family reward EMA decay (default: 0.9).",
    )
    p.add_argument(
        "--families",
        type=str,
        default="sql,xss,cmd",
        help="Comma-separated payload families for arms_from_grid (default: sql,xss,cmd).",
    )
    p.add_argument(
        "--modes",
        type=str,
        default="hybrid,template",
        help="Comma-separated generator modes for arms_from_grid (default: hybrid,template).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    raw = load_raw_context(use_builtin=args.builtin_context, context_path=args.context)
    ctx = RequestContextExtractor().extract(raw)

    families = tuple(s.strip() for s in args.families.split(",") if s.strip())
    modes = tuple(s.strip() for s in args.modes.split(",") if s.strip())
    if len(families) * len(modes) < 2:
        print("error: need at least 2 arms (e.g. two families or two modes).", file=sys.stderr)
        return 2

    arms = arms_from_grid(families, modes)
    tracked = ("sql", "xss", "cmd", "encoded_attack", "other")
    controller = AdaptiveBanditController(
        arms=arms,
        tracked_families=tracked,
        lin_alpha=float(args.lin_alpha),
        memory_decay=float(args.memory_decay),
    )

    print("=== Adaptive selection demo (group D) - offline, no network ===\n")
    print(f"request_id={ctx.request_id!r} method={ctx.method} url={ctx.url!r}")
    print(f"arms ({len(arms)}): {', '.join(a.label for a in arms)}\n")

    rng = random.Random(args.seed) if args.seed is not None else random.Random()
    cumulative = 0.0

    for t in range(int(args.steps)):
        if args.scenario == "scripted":
            preset_name = DEFAULT_SCENARIO_SEQUENCE[t % len(DEFAULT_SCENARIO_SEQUENCE)]
        else:
            preset_name = random_preset(rng)

        decision = controller.select_strategy(ctx)
        outcome = outcome_from_preset(preset_name)

        print(f"--- step {t + 1} ---")
        print(f"  selected_arm: {decision.arm.label}  (index={decision.arm.index})")
        print(format_ucb_line(arms, decision.ucb_scores))
        print(
            f"  fixture_outcome: preset={preset_name!r} -> "
            f"invalid={outcome.invalid_candidate_batch} "
            f"strong_abnormal={outcome.strong_abnormal} "
            f"moderate_differential={outcome.moderate_differential}"
        )
        actual_reward = controller.register_outcome(ctx, decision.arm, outcome)
        cumulative += actual_reward
        print(f"  reward_applied: {actual_reward:.4f}  (cumulative {cumulative:.4f})\n")

    print("--- after learning (one fresh selection) ---")
    final = controller.select_strategy(ctx)
    print(f"  selected_arm: {final.arm.label}")
    print(format_ucb_line(arms, final.ucb_scores))
    print("\nDone. Wire the same controller in your lab driver: pass the chosen arm to")
    print("GenerationRequest.family / options, execute replay, then register_outcome with real OutcomeMetrics.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
