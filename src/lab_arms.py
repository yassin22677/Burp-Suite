"""
Thesis helpers: **separate entry points** for experiment arms A–D (payload side).

- **A** — small fixed baseline list for the workbench (``export_baseline_payloads_for_arm_a``); no KB.
- **B** — static replay: raw ``payload`` strings from ``enriched_payloads.csv`` (no pipeline).
- **C** — retrieval + hybrid transforms + validation + ranking (see :class:`payload_generator.PayloadGenerationPipeline`).
- **D** — full strategy selection in :mod:`experiment_runner` + :mod:`adaptive_controller`; the **workbench**
  uses ``generate_payloads_for_arm_d_ui_simulated``: reads ``trials_C_<request_id>.csv`` when present, scores rows
  (HTTP status-change + normalized length delta), keeps the **top 30%** of rows, deduplicates payloads, and runs
  the hybrid generator on **those seeds only** (no KB retrieval), deterministic transform order, reproducible
  seed from the chosen payloads. Without prior trials, falls back to KB retrieval with deterministic chains.

The Flask workbench and CLIs should route arms explicitly so B never silently uses the
generative pipeline (a common cause of identical B/C outputs).
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Max distinct high-reward payloads passed to the hybrid generator (top-fraction slice may be larger).
_ARM_D_MAX_REWARD_SEEDS = 100

import pandas as pd

from .context_extractor import RequestContext
from .evaluation_pipeline import (
    COL_CANDIDATE,
    COL_CODE_CHANGED,
    compute_length_delta_abs,
    prepare_trial_dataframe,
)
from .experiment_runner import load_static_payloads_from_enriched_kb
from .payload_generator import (
    GenerativeCandidate,
    GenerationRequest,
    PayloadGenerationPipeline,
    sanitize_intruder_lines,
    write_ranked_generative_audit_csv,
)


def sha256_payload_lines(lines: Iterable[str]) -> str:
    """Stable hash over newline-joined payloads (UTF-8)."""
    normalized = "\n".join(str(x) for x in lines)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def set_overlap_rate(a: set[str], b: set[str]) -> float:
    """|A∩B| / max(|A|, |B|, 1) — 1.0 means identical sets when |A|=|B|."""
    if not a and not b:
        return 1.0
    den = max(len(a), len(b), 1)
    return len(a & b) / den


# Fixed baseline list for workbench arm **A** (operator-style generic probes; no KB file).
ARM_A_BASELINE_PAYLOADS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    "test",
    "123",
)


@dataclass
class ArmBatchExport:
    """Paths + diagnostics after writing an arm payload batch to disk."""

    txt_path: Path
    audit_path: Path
    debug_path: Path
    arm: str
    line_count: int
    unique_line_count: int
    lines_preview: list[str]
    payload_set_sha256: str
    overlap_with_prior_static: float | None = None
    debug: dict[str, Any] = field(default_factory=dict)


def static_payload_lines_for_arm_b(
    *,
    kb_path: Path,
    family: str,
    count: int,
    random_seed: int | None = None,
) -> list[str]:
    """Arm **B** lines only (no disk write) — for duplicate checks before export."""
    raw = load_static_payloads_from_enriched_kb(
        kb_path, family, limit=max(0, int(count)), random_seed=random_seed
    )
    return sanitize_intruder_lines([p for p in raw if (p or "").strip()])


def export_baseline_payloads_for_arm_a(
    *,
    txt_path: Path,
    audit_path: Path,
    debug_path: Path,
    lines: list[str] | None = None,
) -> ArmBatchExport:
    """
    Arm **A** — small fixed baseline list for the workbench (no KB, no pipeline).

    Default lines match the thesis “manual baseline” smoke set; override ``lines`` for custom lists.
    """
    src_lines = list(lines) if lines is not None else list(ARM_A_BASELINE_PAYLOADS)
    out_lines = sanitize_intruder_lines([p for p in src_lines if (p or "").strip()])
    uniq = set(out_lines)
    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("\n".join(out_lines) + ("\n" if out_lines else ""), encoding="utf-8")

    with audit_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["line_index", "payload", "arm"])
        for i, p in enumerate(out_lines):
            w.writerow([i, p, "A_baseline_burp"])

    ph = sha256_payload_lines(out_lines)
    debug = {
        "arm": "A_baseline_burp",
        "payload_count": len(out_lines),
        "unique_payload_count": len(uniq),
        "first_10_payloads": out_lines[:10],
        "payload_list_sha256": ph,
        "pipeline_used": False,
        "ranking_used": False,
        "adaptive_used": False,
        "source": "fixed_baseline_list",
    }
    debug_path.write_text(json.dumps(debug, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return ArmBatchExport(
        txt_path=txt_path,
        audit_path=audit_path,
        debug_path=debug_path,
        arm="A_baseline_burp",
        line_count=len(out_lines),
        unique_line_count=len(uniq),
        lines_preview=out_lines[:10],
        payload_set_sha256=ph,
        overlap_with_prior_static=None,
        debug=debug,
    )


def export_static_payloads_for_arm_b(
    *,
    kb_path: Path,
    family: str,
    count: int,
    txt_path: Path,
    audit_path: Path,
    debug_path: Path,
    random_seed: int | None = None,
    other_arm_lines_for_overlap: list[str] | None = None,
) -> ArmBatchExport:
    """
    Arm **B** — enriched KB only: filter ``kb_family``, emit raw payloads (no rank/transform).

    Ordering matches :func:`experiment_runner.load_static_payloads_from_enriched_kb` /
    ``scripts/export_static_payload_batch.py`` (row_id sort, or seeded shuffle).
    """
    lines = static_payload_lines_for_arm_b(
        kb_path=kb_path, family=family, count=count, random_seed=random_seed
    )
    uniq = set(lines)
    overlap = None
    if other_arm_lines_for_overlap is not None:
        overlap = set_overlap_rate(uniq, set(other_arm_lines_for_overlap))

    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    with audit_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["line_index", "payload", "kb_family", "arm"])
        for i, p in enumerate(lines):
            w.writerow([i, p, family, "B_static_dataset"])

    ph = sha256_payload_lines(lines)
    debug = {
        "arm": "B_static_dataset",
        "source_kb": str(kb_path.resolve()),
        "kb_family": family,
        "payload_count": len(lines),
        "unique_payload_count": len(uniq),
        "first_10_payloads": lines[:10],
        "payload_list_sha256": ph,
        "overlap_with_compared_arm": overlap,
        "pipeline_used": False,
        "ranking_used": False,
        "adaptive_used": False,
    }
    debug_path.write_text(json.dumps(debug, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return ArmBatchExport(
        txt_path=txt_path,
        audit_path=audit_path,
        debug_path=debug_path,
        arm="B_static_dataset",
        line_count=len(lines),
        unique_line_count=len(uniq),
        lines_preview=lines[:10],
        payload_set_sha256=ph,
        overlap_with_prior_static=overlap,
        debug=debug,
    )


def generate_payloads_for_arm_c(
    *,
    ctx: RequestContext,
    pipeline: PayloadGenerationPipeline,
    kb_path: Path,
    family: str,
    k_seeds: int,
    n_candidates: int,
    lab_run_id: str,
    options: dict[str, Any] | None,
    txt_path: Path,
    audit_path: Path,
    debug_path: Path,
    static_b_lines_for_overlap: list[str] | None = None,
) -> ArmBatchExport:
    """
    Arm **C** — full generative pipeline with :meth:`PayloadGenerationPipeline.run_with_debug`.

    Output lines are ranked candidates (transformed, validated), not raw KB rows.
    """
    _ = kb_path  # retriever already bound to path; kept for signature symmetry / logging
    opts = dict(options or {})
    opts.setdefault("thesis_arm", "C")
    gen_req = GenerationRequest(
        context=ctx,
        family=family,
        k_seeds=int(k_seeds),
        n_candidates=int(n_candidates),
        lab_run_id=lab_run_id,
        options=opts,
    )
    ranked, trace = pipeline.run_with_debug(gen_req)
    lines = sanitize_intruder_lines([c.value for c in ranked])
    uniq = set(lines)
    overlap = None
    if static_b_lines_for_overlap is not None:
        overlap = set_overlap_rate(uniq, set(static_b_lines_for_overlap))

    trace["payload_list_sha256"] = sha256_payload_lines(lines)
    trace["unique_payload_count"] = len(uniq)
    trace["overlap_with_arm_B_lines"] = overlap
    trace["source_kb"] = str(kb_path.resolve())
    if overlap is not None and overlap >= 0.95 and len(uniq) >= 3:
        trace["warning"] = (
            "Arm C payload set is almost identical to arm B static lines (overlap >= 0.95). "
            "Confirm you used arm C pipeline vs arm B export, and that transforms are active."
        )

    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    write_ranked_generative_audit_csv(audit_path, ranked)

    debug_path.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    ph = trace["payload_list_sha256"]
    return ArmBatchExport(
        txt_path=txt_path,
        audit_path=audit_path,
        debug_path=debug_path,
        arm="C_generated",
        line_count=len(lines),
        unique_line_count=len(uniq),
        lines_preview=lines[:10],
        payload_set_sha256=ph,
        overlap_with_prior_static=overlap,
        debug=trace,
    )


def _load_trials_csv_for_arm_d(path: Path) -> pd.DataFrame | None:
    """Load a normalized trial CSV; return prepared frame or ``None`` if unusable."""
    if not path.is_file():
        return None
    try:
        raw = pd.read_csv(path, engine="python")
    except Exception:
        return None
    if raw.empty:
        return None
    try:
        return prepare_trial_dataframe(raw)
    except Exception:
        return None


def _candidate_cell_str(row: pd.Series) -> str:
    """Normalize ``candidate_value`` for Arm D seeding (pandas reads blank CSV cells as NaN)."""
    raw = row.get(COL_CANDIDATE)
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return ""
    s = str(raw).strip()
    if s.lower() == "nan":
        return ""
    return s


def reward_seed_payloads_from_prepared_trials(
    prepared: pd.DataFrame,
    *,
    top_fraction: float = 0.3,
    max_distinct_cap: int = _ARM_D_MAX_REWARD_SEEDS,
) -> tuple[list[str], dict[str, Any]]:
    """
    Pick distinct ``candidate_value`` strings from the highest-reward trial rows (top ``top_fraction``
    slice by row count, at least one row).

    Score (higher is better): ``float(code_changed) + (|Δlength| / max |Δlength| in table)`` —
    same construction as aggregate ``signal_efficiency`` length term, aligned with HTTP divergence.

    Weak rows (outside the top slice) are never passed to the generator. Returns ordered payloads
    (best score first) and a diagnostics dict including per-payload scores for logging.
    """
    cap = max(1, int(max_distinct_cap))
    if prepared.empty:
        return [], {"reason": "empty_trials", "trial_rows": 0}

    deltas = prepared.apply(compute_length_delta_abs, axis=1)
    dmax = float(deltas.max(skipna=True))
    if not (dmax > 0 and math.isfinite(dmax)):
        dmax = 1.0
    norm = deltas.fillna(0.0).astype(float).clip(lower=0.0) / dmax
    code = prepared[COL_CODE_CHANGED].astype(bool).astype(float)
    score = code + norm
    scored = prepared.assign(_reward_score=score, _abs_len_delta=deltas)
    n = len(scored)
    n_top = max(1, math.ceil(float(top_fraction) * n))
    head = scored.sort_values("_reward_score", ascending=False, kind="mergesort").head(n_top)
    out: list[str] = []
    selection_log: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicate_hits_in_window = 0
    empty_in_window = 0
    hit_cap = False
    for _, row in head.iterrows():
        p = _candidate_cell_str(row)
        if not p:
            empty_in_window += 1
            continue
        sc = float(row["_reward_score"])
        if p in seen:
            duplicate_hits_in_window += 1
            continue
        seen.add(p)
        out.append(p)
        selection_log.append(
            {
                "rank": len(out),
                "score": round(sc, 6),
                "abs_length_delta": float(row["_abs_len_delta"])
                if pd.notna(row["_abs_len_delta"])
                else None,
                "code_changed": bool(row[COL_CODE_CHANGED]),
                "payload_preview": (p[:160] + "…") if len(p) > 160 else p,
            }
        )
        if len(out) >= cap:
            hit_cap = True
            break

    weak_rows_excluded = n - n_top
    diag: dict[str, Any] = {
        "trial_rows": n,
        "top_fraction": float(top_fraction),
        "top_slice_row_count": n_top,
        "weak_rows_excluded": weak_rows_excluded,
        "distinct_high_reward_payloads_kept": len(out),
        "duplicate_payload_rows_skipped_in_window": duplicate_hits_in_window,
        "empty_candidate_rows_in_window": empty_in_window,
        "truncated_by_max_distinct_cap": hit_cap,
        "max_abs_length_delta_observed": dmax,
        "score_formula": "code_changed(0|1) + abs_length_delta / max_abs_length_delta_in_file",
        "adaptive_selection_log": selection_log,
    }
    return out, diag


def distinct_candidates_from_prepared_fallback(
    prepared: pd.DataFrame,
    *,
    max_distinct: int,
) -> tuple[list[str], dict[str, Any]]:
    """
    When ``reward_seed_payloads_from_prepared_trials`` returns no payloads (e.g. top slice rows
    have empty ``candidate_value``), still anchor Arm **D** to this trial file: take the first
    ``max_distinct`` distinct non-empty candidates in **CSV row order** so D does not silently fall
    back to the same KB-only path as Arm **C** (which would duplicate metrics if Intruder used the
    same attack list for both arms).
    """
    cap = max(1, int(max_distinct))
    out: list[str] = []
    seen: set[str] = set()
    for _, row in prepared.iterrows():
        p = _candidate_cell_str(row)
        if not p or p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= cap:
            break
    return out, {
        "trial_rows_scanned": int(len(prepared)),
        "distinct_candidates_taken": len(out),
        "strategy": "row_order_non_empty_candidates",
    }


def run_adaptive_selection_for_arm_d_note() -> str:
    """
    Arm **D** runs inside :class:`experiment_runner.ExperimentRunner` only:

    ``AdaptiveBanditController.select_strategy`` → ``strategy_arm_to_generation_options`` →
    :class:`GenerationRequest` → one top-ranked candidate per round → ``register_outcome``.

    Use ``scripts/run_lab_experiment.py`` with arm D or ``examples/experiment_runner_minimal.py``.
    There is no separate single-function adaptive generator; keeping D in the runner avoids
    duplicating bandit state.
    """
    return (
        "Arm D: use ExperimentRunner._run_arm_d with adaptive_controller configured; "
        "see experiment_runner module docstring."
    )


def generate_payloads_for_arm_d_ui_simulated(
    *,
    ctx: RequestContext,
    pipeline: PayloadGenerationPipeline,
    kb_path: Path,
    family: str,
    k_seeds: int,
    n_candidates: int,
    lab_run_id: str,
    options: dict[str, Any] | None,
    txt_path: Path,
    audit_path: Path,
    debug_path: Path,
    static_b_lines_for_overlap: list[str] | None = None,
    prior_arm_c_trials_path: Path | None = None,
) -> ArmBatchExport:
    """
    Arm **D** in the workbench — **feedback-driven** adaptive batch.

    When ``trials_C_*.csv`` is available, loads trial rows, scores each row with
    ``code_changed + normalized |Δresponse length|``, takes the **top 30%** of rows (by count),
    deduplicates payloads (best score first), and runs the hybrid generator on **those seeds only**
    (no KB retrieval). Transform chains run in **deterministic** sorted order; ``random_seed`` is
    derived from the selected payloads so runs are reproducible without extra randomness.
    Ranked outputs are trimmed to the **top 50%** by score (weaker candidates dropped).

    Without a valid prior file, falls back to KB retrieval with deterministic transform order and a
    stable seed derived from ``request_id`` (not outcome-driven).

    Full LinUCB loops remain in :class:`experiment_runner.ExperimentRunner`.
    """
    _ = kb_path
    opts = dict(options or {})
    opts.setdefault("thesis_arm", "D")

    prior_diag: dict[str, Any] = {}
    prepared = _load_trials_csv_for_arm_d(prior_arm_c_trials_path) if prior_arm_c_trials_path else None
    reward_payloads: list[str] = []
    if prepared is not None and not prepared.empty:
        reward_payloads, prior_diag = reward_seed_payloads_from_prepared_trials(
            prepared,
            top_fraction=0.3,
            max_distinct_cap=_ARM_D_MAX_REWARD_SEEDS,
        )
    if (prepared is not None and not prepared.empty) and not reward_payloads:
        reward_payloads, relax_diag = distinct_candidates_from_prepared_fallback(
            prepared, max_distinct=_ARM_D_MAX_REWARD_SEEDS
        )
        prior_diag = {
            **prior_diag,
            "relaxed_row_order_seed_fallback": True,
            "relaxed_seed_fallback_diag": relax_diag,
        }

    ui_mode = "fallback_kb_deterministic"
    if reward_payloads:
        opts["adaptive_reward_seed_payloads"] = reward_payloads
        opts["adaptive_reward_seeds_only"] = True
        opts["deterministic_transform_order"] = True
        digest = hashlib.sha256(
            (str(ctx.request_id) + "\n" + "\n".join(reward_payloads)).encode("utf-8", errors="replace")
        ).hexdigest()
        opts["random_seed"] = int(digest[:8], 16) % (2**32)
        ui_mode = "feedback_only_reward_seeds"
        if prior_diag.get("relaxed_row_order_seed_fallback"):
            adaptive_note = (
                f"Arm D: {len(reward_payloads)} distinct seed(s) from arm C trials file "
                "(row-order fallback — the top-scoring slice had no usable candidates). "
                "KB retrieval disabled; hybrid transforms only; deterministic chain order."
            )
        else:
            adaptive_note = (
                f"Feedback-driven arm D: {len(reward_payloads)} distinct high-score seed(s) from top "
                f"{int(prior_diag.get('top_fraction', 0.3) * 100)}% of arm C trial rows; "
                f"{prior_diag.get('weak_rows_excluded', 0)} lower-scored row(s) excluded from the seed pool. "
                "KB retrieval disabled; hybrid transforms only; deterministic chain order. "
                "See adaptive_prior_trials_diag.adaptive_selection_log for scores and previews."
            )
    else:
        opts.pop("adaptive_reward_seed_payloads", None)
        opts.pop("adaptive_reward_seeds_only", None)
        fb = hashlib.sha256(
            f"arm_d_fallback|{ctx.request_id}|{lab_run_id}".encode("utf-8", errors="replace")
        ).hexdigest()
        opts["random_seed"] = int(fb[:8], 16) % (2**32)
        opts["deterministic_transform_order"] = True
        adaptive_note = (
            "No valid trials_C file — arm D uses KB retrieval only (deterministic transform order, "
            "stable seed from request_id). Normalize arm C Intruder results first for feedback-driven mode."
        )

    gen_req = GenerationRequest(
        context=ctx,
        family=family,
        k_seeds=max(int(k_seeds), len(reward_payloads)) if reward_payloads else int(k_seeds),
        n_candidates=int(n_candidates),
        lab_run_id=lab_run_id,
        options=opts,
    )
    ranked_forward, trace = pipeline.run_with_debug(gen_req)
    raw_n = len(ranked_forward)
    ranked = list(ranked_forward)
    if ui_mode == "feedback_only_reward_seeds" and ranked:
        keep = max(1, math.ceil(len(ranked) * 0.5))
        ranked = ranked[:keep]
        trace["adaptive_output_trim"] = {
            "kept_top_fraction": 0.5,
            "kept_count": keep,
            "raw_ranked_count": raw_n,
        }
    lines = sanitize_intruder_lines([c.value for c in ranked])
    uniq = set(lines)
    overlap = None
    if static_b_lines_for_overlap is not None:
        overlap = set_overlap_rate(uniq, set(static_b_lines_for_overlap))

    trace["payload_list_sha256"] = sha256_payload_lines(lines)
    trace["unique_payload_count"] = len(uniq)
    trace["overlap_with_arm_B_lines"] = overlap
    trace["source_kb"] = str(kb_path.resolve())
    trace["ui_adaptive_mode"] = ui_mode
    trace["adaptive_prior_trials_diag"] = prior_diag
    trace["adaptive_note"] = adaptive_note
    if overlap is not None and overlap >= 0.95 and len(uniq) >= 3:
        trace["warning"] = (
            "Payload set is almost identical to arm B static lines (overlap >= 0.95). "
            "Confirm KB family and transforms."
        )

    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    write_ranked_generative_audit_csv(audit_path, ranked)

    debug_path.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    ph = trace["payload_list_sha256"]
    return ArmBatchExport(
        txt_path=txt_path,
        audit_path=audit_path,
        debug_path=debug_path,
        arm="D_generated_adaptive",
        line_count=len(lines),
        unique_line_count=len(uniq),
        lines_preview=lines[:10],
        payload_set_sha256=ph,
        overlap_with_prior_static=overlap,
        debug=trace,
    )


def generative_candidates_differ_from_raw_seeds(ranked: list[GenerativeCandidate], seeds: list[str]) -> bool:
    """True if at least one ranked value is not exactly a retrieved seed string."""
    seed_set = {s.strip() for s in seeds if s.strip()}
    for c in ranked:
        if c.value.strip() not in seed_set:
            return True
    return False
