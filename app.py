"""
Single-page Flask UI for the **manual / offline** Burp workflow (graduation helper).

Uses existing ``src`` modules only — no Burp connection, no auth, no DB.

Run locally (from repository root)::

    pip install flask pandas numpy
    python app.py

Then open http://127.0.0.1:5055 in a browser.

Downloads: ``GET /download/results/<filename>`` and ``GET /download/requests/<filename>`` serve
files from ``ui_workspace/results`` and ``ui_workspace/requests`` when the basename is allow-listed.

Workspace (created automatically):

- ``ui_workspace/requests/`` — saved request JSON
- ``ui_workspace/results/`` — generated payloads, trial CSVs, comparison metrics
- ``ui_workspace/uploads/`` — uploaded Burp exports

**Stages in this UI (see docs/MANUAL_LAB_WORKFLOW.md):** (1) Step 1 — payload arm **A–D**:
``*_armA.txt`` (fixed baseline), ``*_armB_static*`` (KB replay), ``*_armC_generated*`` (pipeline),
``*_armD.txt`` (with ``trials_C_<id>.csv``: top 30% trial rows scored by status-change + normalized length
delta become the **only** hybrid seeds — no KB; deterministic chain order; full bandit in ``ExperimentRunner``); (2) Step 2 — normalize Burp exports → ``trials_<A–D>_<request_id>.csv``;
(3) Step 3 — aggregate → ``comparison_metrics.csv``.

Note: ``import app`` resolves to the ``app/`` **package** (RL backend). Always start
this workbench with ``python app.py`` so this **file** runs as ``__main__``.
"""

from __future__ import annotations

import importlib.util
import copy
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from flask import Flask, abort, render_template, request, send_file, session, url_for

# Repository root = directory containing this file
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.context_extractor import RequestContextExtractor
from src.evaluation_pipeline import (
    burp_intruder_to_prepared_dataframe,
    canonical_experiment_group,
    prepare_trial_dataframe,
    run_full_comparison_and_save,
)
from src.lab_arms import (
    ARM_A_BASELINE_PAYLOADS,
    export_baseline_payloads_for_arm_a,
    export_static_payloads_for_arm_b,
    generate_payloads_for_arm_c,
    generate_payloads_for_arm_d_ui_simulated,
    static_payload_lines_for_arm_b,
)
from src.payload_generator import (
    EnrichedCsvSeedRetriever,
    HybridCandidateGenerator,
    PayloadGenerationPipeline,
    PermissiveLabValidator,
)
from src.payload_ranker import MultiFactorExplainableRanker
from workbench_helpers import (
    AGGREGATE_INVALID_SELECTION_MSG,
    AGGREGATE_WARNING_MESSAGES,
    duplicate_payload_list_errors_vs_sibling_arms,
    filter_aggregate_selection_to_allowed,
    experiment_group_letter,
    format_user_facing_error,
    hash_normalized_candidate_column,
    is_allowed_results_download,
    list_normalized_trial_csvs,
    load_trial_frames_for_aggregate,
    normalize_cross_arm_duplicate_warnings,
    path_normalized_trial_csv,
    path_request_json,
    paths_arm_payload_outputs,
    read_burp_intruder_export_tolerant,
    save_uploaded_burp_export,
    unlink_arm_payload_outputs,
    validate_baseline_for_normalize,
)

WS = REPO_ROOT / "ui_workspace"
REQUESTS_DIR = WS / "requests"
RESULTS_DIR = WS / "results"
UPLOADS_DIR = WS / "uploads"

FAMILIES = ("sql", "xss", "cmd", "encoded_attack", "other")
MAX_PREVIEW_LINES = 40
# Cap lines rendered in the HTML payload list (full count still used for the success message).
MAX_UI_PAYLOAD_LINES = 5000
MAX_METRICS_ROWS = 20

# Default aggregate preview: small headline table only (full metrics → CSV + debug “More columns”).
WORKBENCH_METRICS_MAIN_COLUMNS: tuple[str, ...] = (
    "experiment_group",
    "trial_count",
    "response_code_change_rate",
    "abnormal_rate",
    "signal_efficiency",
)

_METRICS_GROUP_LABELS: dict[str, str] = {
    "A_baseline_burp": "Arm A (baseline)",
    "B_static_dataset": "Arm B (static KB)",
    "C_generated": "Arm C (generated)",
    "D_generated_adaptive": "Arm D (adaptive)",
}

flask_app = Flask(__name__, template_folder="templates", static_folder="static")


def _format_metric_float_cell(v: Any) -> str:
    if pd.isna(v):
        return "—"
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    if not np.isfinite(f):
        return "—"
    return f"{f:.2f}"


def _workbench_metrics_main_table(metrics: pd.DataFrame) -> pd.DataFrame:
    """Columns shown in the workbench aggregate preview; group ids get short labels."""
    cols = [c for c in WORKBENCH_METRICS_MAIN_COLUMNS if c in metrics.columns]
    main = metrics.loc[:, cols].copy()
    if "experiment_group" in main.columns:
        main["experiment_group"] = main["experiment_group"].map(_metrics_group_label)
    return main


def _format_metrics_for_display(df: pd.DataFrame) -> pd.DataFrame:
    """Build a string copy for HTML: floats to 2 decimals, ints plain, NaN as —."""
    out = df.copy()
    for col in out.columns:
        ser = out[col]
        if pd.api.types.is_bool_dtype(ser):
            out[col] = ser.map(lambda v: "—" if pd.isna(v) else ("Yes" if bool(v) else "No"))
            continue
        if not pd.api.types.is_numeric_dtype(ser):
            out[col] = ser.map(lambda v: "—" if pd.isna(v) else str(v))
            continue
        if pd.api.types.is_integer_dtype(ser):
            out[col] = ser.map(lambda v: "—" if pd.isna(v) else str(int(v)))
            continue
        out[col] = ser.map(_format_metric_float_cell)
    return out


def _metrics_group_label(group_val: Any) -> str:
    s = str(group_val).strip() if group_val is not None else ""
    if not s or s.lower() == "nan":
        return "—"
    return _METRICS_GROUP_LABELS.get(s, s)


def _arms_outcome_metrics_tied(metrics: pd.DataFrame) -> bool:
    """
    True when displayed comparison metrics are identical across all arms (common when the server
    returned the same status/length pattern for two different payload lists).
    """
    if metrics is None or len(metrics) < 2:
        return False
    cols = [
        c
        for c in (
            "trial_count",
            "response_code_change_rate",
            "avg_abs_length_delta",
            "signal_efficiency",
        )
        if c in metrics.columns
    ]
    if not cols:
        return False
    for c in cols:
        s = pd.to_numeric(metrics[c], errors="coerce")
        if s.empty:
            return False
        vmin = float(s.min())
        vmax = float(s.max())
        if not (np.isfinite(vmin) and np.isfinite(vmax)):
            return False
        if not np.isclose(vmin, vmax, rtol=1e-9, atol=1e-6):
            return False
    return True


def build_metrics_comparison_summary(metrics: pd.DataFrame) -> str:
    """
    Short auto-generated prose for the workbench (viva-friendly).
    Uses numeric maxima per column; ties break by first row order.
    """
    if metrics is None or metrics.empty:
        return ""
    gcol = "experiment_group"

    if _arms_outcome_metrics_tied(metrics):
        msg = (
            "All selected arms show the same values here because observed HTTP outcomes (status and response "
            "length vs baseline) aggregate the same way for each file — the server often replies identically "
            "to different payloads. This is expected; it is not a bug. See diagnostics for Overlap. "
            "Arm D uses arm C trials to build the next payload file; it does not change numbers already saved "
            "in your trial CSVs."
        )
        if "payload_column_fp" in metrics.columns:
            fp = metrics["payload_column_fp"].astype(str)
            if fp.nunique(dropna=False) > 1:
                msg += (
                    " The table’s payload_column_fp column should differ per arm when Intruder payload columns "
                    "differ, even if outcome metrics match."
                )
        return msg

    parts: list[str] = []

    def _best(col: str) -> tuple[Any, float] | None:
        if col not in metrics.columns or gcol not in metrics.columns:
            return None
        s = pd.to_numeric(metrics[col], errors="coerce")
        if s.notna().sum() == 0:
            return None
        idx = s.idxmax()
        val = float(s.loc[idx])
        grp = metrics.loc[idx, gcol]
        return grp, val

    br = _best("response_code_change_rate")
    if br:
        parts.append(
            f"{_metrics_group_label(br[0])} had the highest HTTP status–change rate "
            f"({br[1]:.2f} of trials)."
        )
    bl = _best("avg_abs_length_delta")
    if bl:
        parts.append(
            f"{_metrics_group_label(bl[0])} had the largest average absolute response-length delta "
            f"({bl[1]:.2f} bytes)."
        )
    if "signal_efficiency" in metrics.columns:
        be = _best("signal_efficiency")
        if be:
            parts.append(
                f"{_metrics_group_label(be[0])} leads on the combined signal_efficiency score "
                f"({be[1]:.2f} on a 0–1 scale)."
            )

    if gcol in metrics.columns and len(metrics) >= 2:
        idxed = metrics.set_index(gcol)
        if "A_baseline_burp" in idxed.index and "B_static_dataset" in idxed.index:
            if "signal_efficiency" in metrics.columns:
                a = pd.to_numeric(idxed.loc["A_baseline_burp", "signal_efficiency"], errors="coerce")
                b = pd.to_numeric(idxed.loc["B_static_dataset", "signal_efficiency"], errors="coerce")
                a_f = 0.0 if pd.isna(a) else float(a)
                b_f = 0.0 if pd.isna(b) else float(b)
                if b_f > a_f:
                    parts.append("Arm B shows higher signal_efficiency than Arm A in this run.")
                elif a_f > b_f:
                    parts.append("Arm A shows higher signal_efficiency than Arm B in this run.")

    return " ".join(parts)


flask_app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
# Reload templates from disk even when debug=False (avoids “UI never updates” after edits).
flask_app.config["TEMPLATES_AUTO_RELOAD"] = True
flask_app.secret_key = os.environ.get(
    "WORKBENCH_SECRET_KEY",
    "workbench-dev-secret-change-for-deployment",
)

_log = logging.getLogger(__name__)

# Technical UI (paths, parse previews, aggregate diagnostics, full metrics table): set
# BURP_WORKBENCH_DEBUG_UI=1 (or true/yes/on) in the environment before starting ``python app.py``.
# (Previously an on-page "Advanced" form stored a session flag; that control was removed for a cleaner UI.)
_norm_script_mod: Any = None


def _env_debug_ui() -> bool:
    v = (os.environ.get("BURP_WORKBENCH_DEBUG_UI") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def workbench_debug_ui_enabled() -> bool:
    """True if technical / debug blocks should appear in the HTML UI (environment only)."""
    return _env_debug_ui()


def _friendly_normalize_ok(n: int) -> str:
    if n <= 0:
        return "No trial rows were written."
    return f"Normalized {n} trial row{'s' if n != 1 else ''}."


def _apply_workbench_presentation(
    gen_out: dict[str, Any] | None,
    norm_out: dict[str, Any] | None,
    agg_out: dict[str, Any] | None,
    *,
    debug_ui: bool,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Strip or rewrite UI-facing dicts for demo mode; log removed details."""
    g = copy.deepcopy(gen_out) if gen_out else None
    n = copy.deepcopy(norm_out) if norm_out else None
    a = copy.deepcopy(agg_out) if agg_out else None

    if g and "error" not in g:
        # Generate success banner text is fixed in lab_workbench.html ("success"); never pass verbose ok.
        g.pop("ok", None)
        if not debug_ui:
            g.pop("preview", None)
            outputs = g.get("outputs") or []
            g["outputs"] = [o for o in outputs if o.get("label") == "txt"]

    if n:
        if "error" not in n:
            rows = int(n.get("rows") or 0)
            n["ok"] = _friendly_normalize_ok(rows)
            if not debug_ui:
                for w in n.get("normalize_warnings") or []:
                    _log.warning("workbench normalize: %s", w)
                n.pop("normalize_warnings", None)
                n.pop("normalize_diagnostics", None)
        elif not debug_ui:
            n.pop("normalize_diagnostics", None)

    if a and "error" not in a:
        if not debug_ui:
            dt = a.get("diagnostics_text")
            if dt:
                _log.info("workbench aggregate diagnostics:\n%s", dt)
            a.pop("diagnostics_text", None)
            a.pop("table_html_full", None)
            a["ok"] = "Comparison metrics saved."
    return g, n, a


def _load_normalize_script() -> Any:
    global _norm_script_mod
    if _norm_script_mod is None:
        path = REPO_ROOT / "scripts" / "normalize_burp_results.py"
        spec = importlib.util.spec_from_file_location("_normalize_burp_results_ui", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Cannot load normalize_burp_results.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _norm_script_mod = mod
    return _norm_script_mod


def ensure_workspace() -> None:
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def safe_fs_part(s: str) -> str:
    """Safe filename stem; keeps most characters, strips path separators."""
    t = (s or "").strip()
    for ch in '<>:"/\\|?*\n\r\t\x00':
        t = t.replace(ch, "_")
    return t[:200] if t else "request"


def build_pipeline(kb_path: Path, *, permissive: bool) -> PayloadGenerationPipeline:
    retriever = EnrichedCsvSeedRetriever(kb_path)
    generator = HybridCandidateGenerator()
    ranker = MultiFactorExplainableRanker()
    validator = PermissiveLabValidator() if permissive else None
    return PayloadGenerationPipeline(retriever, generator, ranker, validator=validator)


def default_form_values() -> dict[str, Any]:
    return {
        "request_id": "lab_ui_01",
        "method": "GET",
        "url": "https://lab.example/api/search?q=",
        "content_type": "",
        "parameter_name": "q",
        "parameter_location": "query",
        "family": "xss",
        "k_seeds": 5,
        "n_candidates": 12,
        "kb_path": str(REPO_ROOT / "data" / "enriched_payloads.csv"),
        "permissive": False,
        "payload_arm": "C",
    }


def default_norm_values() -> dict[str, Any]:
    return {
        "group": "A",
        "baseline_status": 200,
        "baseline_length": 1000,
        "trial_id_prefix": "trial",
        "sep": "auto",
    }


def _session_get_form_defaults() -> dict[str, Any]:
    raw = session.get("workbench_defaults")
    if not isinstance(raw, dict):
        return default_form_values()
    merged = default_form_values()
    for k in merged:
        if k in raw:
            merged[k] = raw[k]
    return merged


def _session_get_norm_defaults() -> dict[str, Any]:
    raw = session.get("workbench_norm_defaults")
    if not isinstance(raw, dict):
        return default_norm_values()
    merged = default_norm_values()
    for k in merged:
        if k in raw:
            merged[k] = raw[k]
    return merged


def _session_save_form_defaults(d: dict[str, Any]) -> None:
    session["workbench_defaults"] = {k: d[k] for k in default_form_values()}


def _session_save_norm_defaults(n: dict[str, Any]) -> None:
    session["workbench_norm_defaults"] = {k: n[k] for k in default_norm_values()}


def parse_generate_form(form: Any) -> dict[str, Any]:
    d = default_form_values()
    d["request_id"] = (form.get("request_id") or "").strip() or d["request_id"]
    d["method"] = (form.get("method") or "GET").strip().upper()
    if d["method"] not in ("GET", "POST"):
        d["method"] = "GET"
    d["url"] = (form.get("url") or "").strip() or d["url"]
    d["content_type"] = (form.get("content_type") or "").strip()
    d["parameter_name"] = (form.get("parameter_name") or "").strip() or "param"
    loc = (form.get("parameter_location") or "query").strip().lower()
    if loc not in ("query", "body_form", "json"):
        loc = "query"
    if d["method"] == "GET" and not (form.get("parameter_location") or "").strip():
        loc = "query"
    d["parameter_location"] = loc
    fam = (form.get("family") or "xss").strip().lower()
    d["family"] = fam if fam in FAMILIES else "xss"
    try:
        d["k_seeds"] = max(1, int(form.get("k_seeds") or 5))
    except (TypeError, ValueError):
        d["k_seeds"] = 5
    try:
        d["n_candidates"] = max(1, int(form.get("n_candidates") or 12))
    except (TypeError, ValueError):
        d["n_candidates"] = 12
    d["kb_path"] = (form.get("kb_path") or "").strip() or str(REPO_ROOT / "data" / "enriched_payloads.csv")
    d["permissive"] = form.get("permissive") == "1"
    pa = (form.get("payload_arm") or "C").strip().upper()
    d["payload_arm"] = pa if pa in ("A", "B", "C", "D") else "C"
    return d


def parse_norm_form(form: Any) -> dict[str, Any]:
    n = default_norm_values()
    g = (form.get("group") or "A").strip().upper()[:1]
    n["group"] = g if g in "ABCD" else "A"
    try:
        n["baseline_status"] = int(form.get("baseline_status") or 200)
    except (TypeError, ValueError):
        n["baseline_status"] = 200
    try:
        n["baseline_length"] = int(form.get("baseline_length") or 0)
    except (TypeError, ValueError):
        n["baseline_length"] = 0
    n["trial_id_prefix"] = (form.get("trial_id_prefix") or "trial").strip() or "trial"
    sep = (form.get("sep") or "auto").strip().lower()
    n["sep"] = sep if sep in ("auto", "tab", "comma") else "auto"
    return n


def _download_url(kind: str, basename: str) -> str | None:
    if kind == "results":
        if not is_allowed_results_download(basename):
            return None
    elif kind == "requests":
        b = Path(basename).name
        if b != basename or not b.endswith(".json"):
            return None
    else:
        return None
    return url_for("download_workspace_file", kind=kind, filename=basename)


def run_generate(d: dict[str, Any]) -> dict[str, Any]:
    ensure_workspace()
    rid_fs = safe_fs_part(d["request_id"])
    req_path = path_request_json(REQUESTS_DIR, rid_fs)
    arm = (d.get("payload_arm") or "C").strip().upper()
    if arm not in ("A", "B", "C", "D"):
        arm = "C"
    txt_path, audit_path, debug_path = paths_arm_payload_outputs(RESULTS_DIR, rid_fs, arm)

    param = {
        "name": d["parameter_name"],
        "location": d["parameter_location"],
        "declared_type": "string",
    }
    raw: dict[str, Any] = {
        "request_id": d["request_id"],
        "method": d["method"],
        "url": d["url"],
        "parameters": [param],
    }
    if d["content_type"]:
        raw["content_type"] = d["content_type"]

    kb_path = Path(d["kb_path"])
    if arm != "A" and not kb_path.is_file():
        return {"error": f"Enriched KB not found: {kb_path}"}

    req_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    ctx = RequestContextExtractor().extract(raw)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    def _dup_err(proposed_lines: list[str]) -> str | None:
        errs = duplicate_payload_list_errors_vs_sibling_arms(RESULTS_DIR, rid_fs, arm, proposed_lines)
        return errs[0] if errs else None

    if arm == "A":
        prop_lines = [ln for ln in ARM_A_BASELINE_PAYLOADS if (ln or "").strip()]
        de = _dup_err(prop_lines)
        if de:
            return {"error": de}
        export_baseline_payloads_for_arm_a(
            txt_path=txt_path,
            audit_path=audit_path,
            debug_path=debug_path,
        )
    elif arm == "B":
        prop_lines = static_payload_lines_for_arm_b(
            kb_path=kb_path,
            family=d["family"],
            count=int(d["n_candidates"]),
            random_seed=None,
        )
        de = _dup_err(prop_lines)
        if de:
            return {"error": de}
        export_static_payloads_for_arm_b(
            kb_path=kb_path,
            family=d["family"],
            count=int(d["n_candidates"]),
            txt_path=txt_path,
            audit_path=audit_path,
            debug_path=debug_path,
            random_seed=None,
            other_arm_lines_for_overlap=None,
        )
    else:
        b_txt = RESULTS_DIR / f"{rid_fs}_armB_static.txt"
        static_lines: list[str] | None = None
        if b_txt.is_file():
            static_lines = [ln.strip() for ln in b_txt.read_text(encoding="utf-8").splitlines() if ln.strip()]
        pipeline = build_pipeline(kb_path, permissive=bool(d["permissive"]))
        if arm == "C":
            generate_payloads_for_arm_c(
                ctx=ctx,
                pipeline=pipeline,
                kb_path=kb_path,
                family=d["family"],
                k_seeds=int(d["k_seeds"]),
                n_candidates=int(d["n_candidates"]),
                lab_run_id=f"ui_{rid_fs}",
                options={},
                txt_path=txt_path,
                audit_path=audit_path,
                debug_path=debug_path,
                static_b_lines_for_overlap=static_lines,
            )
        else:
            prior_c_trials = RESULTS_DIR / f"trials_C_{rid_fs}.csv"
            generate_payloads_for_arm_d_ui_simulated(
                ctx=ctx,
                pipeline=pipeline,
                kb_path=kb_path,
                family=d["family"],
                k_seeds=int(d["k_seeds"]),
                n_candidates=int(d["n_candidates"]),
                lab_run_id=f"ui_{rid_fs}_d",
                options={},
                txt_path=txt_path,
                audit_path=audit_path,
                debug_path=debug_path,
                static_b_lines_for_overlap=static_lines,
                prior_arm_c_trials_path=prior_c_trials,
            )

    text = txt_path.read_text(encoding="utf-8") if txt_path.is_file() else ""
    safe_lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    dup_after = _dup_err(safe_lines)
    if dup_after:
        unlink_arm_payload_outputs((txt_path, audit_path, debug_path))
        return {"error": dup_after}

    preview = "\n".join(safe_lines[:MAX_PREVIEW_LINES])
    n_all = len(safe_lines)
    ui_lines = safe_lines if n_all <= MAX_UI_PAYLOAD_LINES else safe_lines[:MAX_UI_PAYLOAD_LINES]
    if n_all > MAX_UI_PAYLOAD_LINES:
        _log.warning(
            "workbench generate: UI payload list truncated (%s lines, cap %s)",
            n_all,
            MAX_UI_PAYLOAD_LINES,
        )

    out: dict[str, Any] = {
        "payload_count": n_all,
        "payload_lines": ui_lines,
        "outputs": [
            {"label": "json", "path": str(req_path), "file": req_path.name, "download_kind": "requests"},
            {"label": "txt", "path": str(txt_path), "file": txt_path.name, "download_kind": "results"},
            {"label": "csv", "path": str(audit_path), "file": audit_path.name, "download_kind": "results"},
            {"label": "json", "path": str(debug_path), "file": debug_path.name, "download_kind": "results"},
        ],
        "preview": preview,
    }
    _log.info("workbench generate: arm=%s request_id_fs=%s payload_count=%s", arm, rid_fs, n_all)
    if arm == "D" and debug_path.is_file():
        try:
            dbg = json.loads(debug_path.read_text(encoding="utf-8"))
            note = dbg.get("adaptive_note")
            if note:
                _log.info("workbench generate arm D: %s", note)
        except (json.JSONDecodeError, OSError, TypeError):
            pass
    return out


def run_normalize(
    *,
    upload_path: Path,
    group: str,
    request_id: str,
    baseline_status: int,
    baseline_length: int,
    trial_id_prefix: str,
    sep: str,
) -> dict[str, Any]:
    ensure_workspace()
    mod = _load_normalize_script()
    apply_abnormality_rules = mod.apply_abnormality_rules

    gl = experiment_group_letter(group)
    if gl is None:
        return {"error": "Choose a valid experiment group A, B, C, or D."}

    ok_bl, bl_err = validate_baseline_for_normalize(baseline_status, baseline_length)
    if not ok_bl:
        return {"error": bl_err or "Invalid baseline values."}

    raw, read_err, parse_diag = read_burp_intruder_export_tolerant(upload_path, sep=sep)
    if raw is None or read_err:
        return {
            "error": read_err
            or "Could not read the uploaded export (encoding or format). Try another separator or save as UTF-8 CSV.",
            "normalize_diagnostics": parse_diag,
        }

    group_canon = canonical_experiment_group(group)
    rid_fs = safe_fs_part(request_id)
    out_path = path_normalized_trial_csv(RESULTS_DIR, gl, rid_fs)

    try:
        prepared = burp_intruder_to_prepared_dataframe(
            raw,
            experiment_group=group_canon,
            request_id=str(request_id),
            baseline_status_code=baseline_status,
            baseline_response_length=baseline_length,
            trial_id_prefix=str(trial_id_prefix or "trial"),
            column_overrides=None,
            infer_abnormal_from_response=False,
        )
    except ValueError as e:
        cols = parse_diag.get("column_names") or []
        return {
            "error": (
                f"Could not map Burp columns to payload / status / length. {e} "
                f"Columns found ({len(cols)}): {', '.join(str(c) for c in cols[:20])}"
                + (" …" if len(cols) > 20 else "")
                + ". Use names containing Payload, Status, and Length (or extend the CLI with column maps)."
            ),
            "normalize_diagnostics": parse_diag,
        }
    except (TypeError, KeyError) as e:
        _log.exception("Normalize mapping failed after parse")
        return {
            "error": "Normalization failed while building trial rows. Check that the export is an Intruder results table.",
            "normalize_diagnostics": parse_diag,
        }

    parse_cols_safe = [str(c) for c in (parse_diag.get("column_names") or [])]
    try:
        prepared = apply_abnormality_rules(
            prepared,
            abnormal_on_status_change=True,
            abnormal_on_length_delta=True,
            length_delta_threshold=100.0,
        )
        prepared = prepare_trial_dataframe(prepared)
        cand_sha = hash_normalized_candidate_column(prepared)
        cross_arm_warnings = normalize_cross_arm_duplicate_warnings(RESULTS_DIR, rid_fs, gl, cand_sha)
        prepared.to_csv(out_path, index=False, encoding="utf-8")
    except TypeError as e:
        msg = str(e)
        _log.exception("Normalize post-process failed (often float/str mix in export)")
        if "str instance" in msg or "join" in msg.lower():
            return {
                "error": (
                    "Could not finish normalization: the export had mixed cell types (often Excel/Burp turned "
                    "some cells into numbers). Re-save the file as UTF-8 CSV, or try separator comma vs auto."
                ),
                "normalize_diagnostics": {
                    **parse_diag,
                    "parse_columns": parse_cols_safe,
                    "parse_encoding": parse_diag.get("encoding"),
                    "parse_separator": parse_diag.get("separator"),
                    "parse_row_count": parse_diag.get("row_count_parsed"),
                },
            }
        return {
            "error": format_user_facing_error(e),
            "normalize_diagnostics": {**parse_diag, "parse_columns": parse_cols_safe},
        }

    _log.info(
        "workbench normalize: input=%s encoding=%s separator=%s rows_parsed=%s out=%s trial_rows=%s",
        upload_path.name,
        parse_diag.get("encoding"),
        parse_diag.get("separator"),
        parse_diag.get("row_count_parsed"),
        out_path,
        len(prepared),
    )

    out: dict[str, Any] = {
        "ok": f"{len(prepared)} rows",
        "outputs": [
            {
                "label": "csv",
                "path": str(out_path),
                "file": out_path.name,
                "download_kind": "results",
            },
        ],
        "rows": len(prepared),
        "normalize_diagnostics": {
            "group_letter": gl,
            "request_id_fs": rid_fs,
            "candidate_column_sha256": cand_sha,
            "parse_encoding": parse_diag.get("encoding"),
            "parse_separator": parse_diag.get("separator"),
            "parse_columns": parse_cols_safe,
            "parse_row_count": parse_diag.get("row_count_parsed"),
            "parse_preview_rows": parse_diag.get("preview_rows"),
        },
        "normalize_warnings": cross_arm_warnings,
    }
    return out


def run_aggregate(filenames: list[str]) -> dict[str, Any]:
    ensure_workspace()
    try:
        frames, err, report = load_trial_frames_for_aggregate(RESULTS_DIR, filenames)
        if err or frames is None:
            return {"error": err or AGGREGATE_INVALID_SELECTION_MSG}

        out_path = RESULTS_DIR / "comparison_metrics.csv"
        metrics, written = run_full_comparison_and_save(
            frames,
            output_path=out_path,
            repo_root=REPO_ROOT,
        )
        head = metrics.head(MAX_METRICS_ROWS).copy()
        display_full = _format_metrics_for_display(head)
        table_html_full = display_full.to_html(index=False, classes=["preview", "metrics-table"])
        main_head = _workbench_metrics_main_table(head)
        table_html = _format_metrics_for_display(main_head).to_html(
            index=False, classes=["preview", "metrics-table"]
        )
    except Exception:
        _log.exception("Section 3 aggregate failed")
        return {"error": AGGREGATE_INVALID_SELECTION_MSG}

    diag_lines: list[str] = []
    if report:
        for row in report.get("per_file", []):
            diag_lines.append(
                f"{row.get('file')}: rows={row.get('rows')} group={row.get('experiment_group')} "
                f"candidate_sha256={row.get('candidate_column_sha256', '')[:16]}…"
            )
        for w in report.get("warnings", []):
            diag_lines.append(f"Warning: {w}")
        for pr in report.get("pairwise_candidate_overlap", []):
            diag_lines.append(
                f"Overlap {pr.get('left_file')} vs {pr.get('right_file')}: "
                f"{float(pr.get('overlap_rate', 0)):.3f} "
                f"(distinct {pr.get('left_distinct')}/{pr.get('right_distinct')})"
            )

    out: dict[str, Any] = {
        "ok": f"{len(metrics)} arms",
        "outputs": [
            {
                "label": "comparison_metrics.csv",
                "path": str(written),
                "file": written.name,
                "download_kind": "results",
            },
        ],
        "table_html": table_html,
        "table_html_full": table_html_full,
    }
    if diag_lines:
        out["diagnostics_text"] = "\n".join(diag_lines)
    return out


@flask_app.route("/download/<string:kind>/<path:filename>")
def download_workspace_file(kind: str, filename: str):
    """Download allowed files from ``ui_workspace/results`` or ``ui_workspace/requests``."""
    base = Path(filename).name
    if base != filename or ".." in base:
        abort(404)
    if kind == "results":
        if not is_allowed_results_download(base):
            abort(404)
        root = RESULTS_DIR.resolve()
    elif kind == "requests":
        if not base.endswith(".json"):
            abort(404)
        root = REQUESTS_DIR.resolve()
    else:
        abort(404)
    path = (root / base).resolve()
    if not path.is_file() or path.parent != root:
        abort(404)
    return send_file(path, as_attachment=True, download_name=base)


@flask_app.route("/", methods=["GET", "POST"])
def index() -> str:
    ensure_workspace()
    gen_out: dict[str, Any] | None = None
    norm_out: dict[str, Any] | None = None
    agg_out: dict[str, Any] | None = None
    defaults = _session_get_form_defaults()
    norm_defaults = _session_get_norm_defaults()
    selected_trials: list[str] = []

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if action == "generate":
            try:
                defaults = parse_generate_form(request.form)
                gen_out = run_generate(defaults)
            except Exception as e:
                _log.exception("Section 1 generate failed")
                gen_out = {"error": format_user_facing_error(e)}
                defaults = parse_generate_form(request.form)
            _session_save_form_defaults(defaults)
        elif action == "normalize":
            norm_defaults = parse_norm_form(request.form)
            defaults = _session_get_form_defaults()
            rid_input = (request.form.get("n_request_id") or defaults["request_id"]).strip()
            defaults["request_id"] = rid_input or defaults["request_id"]
            f = request.files.get("burp_file")
            if not f or not f.filename:
                norm_out = {"error": "No file uploaded."}
            else:
                try:
                    up_path = save_uploaded_burp_export(f, UPLOADS_DIR)
                    rid = (request.form.get("n_request_id") or "").strip()
                    if not rid:
                        norm_out = {"error": "request_id is required."}
                    else:
                        norm_out = run_normalize(
                            upload_path=up_path,
                            group=norm_defaults["group"],
                            request_id=rid,
                            baseline_status=int(norm_defaults["baseline_status"]),
                            baseline_length=int(norm_defaults["baseline_length"]),
                            trial_id_prefix=str(norm_defaults["trial_id_prefix"]),
                            sep=str(norm_defaults["sep"]),
                        )
                except Exception as e:
                    _log.exception("Section 2 normalize failed")
                    norm_out = {"error": format_user_facing_error(e)}
            _session_save_form_defaults(defaults)
            _session_save_norm_defaults(norm_defaults)
        elif action == "aggregate":
            allowed = frozenset(list_normalized_trial_csvs(RESULTS_DIR))
            raw_selected = request.form.getlist("trial_csv")
            selected_trials = filter_aggregate_selection_to_allowed(raw_selected, allowed)
            if raw_selected and not selected_trials:
                agg_out = {"error": AGGREGATE_INVALID_SELECTION_MSG}
            else:
                try:
                    agg_out = run_aggregate(selected_trials)
                except Exception:
                    _log.exception("Section 3 aggregate failed (unexpected)")
                    agg_out = {"error": AGGREGATE_INVALID_SELECTION_MSG}
        else:
            gen_out = {"error": f"Unknown action: {action!r}"}

    # Attach download links for result dicts
    for block in (gen_out, norm_out, agg_out):
        if not block or "outputs" not in block:
            continue
        for o in block["outputs"]:
            fn = o.get("file")
            dk = o.get("download_kind")
            if fn and dk:
                o["download_url"] = _download_url(str(dk), str(fn))

    trial_csv_choices = list_normalized_trial_csvs(RESULTS_DIR)

    if request.method == "POST":
        posted_action = (request.form.get("action") or "").strip()
        if posted_action == "aggregate":
            session["workbench_selected_trials"] = selected_trials

    if not selected_trials:
        st = session.get("workbench_selected_trials")
        if isinstance(st, list) and all(isinstance(x, str) for x in st):
            selected_trials = [x for x in st if x in trial_csv_choices]

    debug_ui = workbench_debug_ui_enabled()
    gen_out, norm_out, agg_out = _apply_workbench_presentation(
        gen_out, norm_out, agg_out, debug_ui=debug_ui
    )

    return render_template(
        "lab_workbench.html",
        gen=gen_out,
        norm=norm_out,
        agg=agg_out,
        defaults=defaults,
        norm_defaults=norm_defaults,
        families=FAMILIES,
        trial_csv_choices=trial_csv_choices,
        selected_trials=selected_trials,
        aggregate_warning_messages=AGGREGATE_WARNING_MESSAGES,
        debug_ui=debug_ui,
    )


if __name__ == "__main__":
    ensure_workspace()
    _tpl = (REPO_ROOT / "templates" / "lab_workbench.html").resolve()
    print(
        "[workbench] Step 1 includes arms A–D. Serving template from:",
        _tpl,
        "(restart this process after pulling git changes; hard-refresh the browser.)",
        flush=True,
    )
    flask_app.run(host="127.0.0.1", port=5055, debug=False)
