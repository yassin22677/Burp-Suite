"""
Evaluation pipeline: load trial logs, derive fields, aggregate metrics for groups A–D.

This repository targets an **offline, manual Burp-assisted** workflow: you generate
payloads in Python, run Intruder yourself, save result tables to files, then use this
module (or ``scripts/normalize_burp_results.py``) to normalize and aggregate. There is
**no** live connection to Burp, Intruder automation, or remote LLM generation.

**Experiment groups** (:class:`~src.evaluation.ExperimentGroup`):

- **A** — Baseline comparison payloads (operator-supplied strings)
- **B** — Static KB payloads (no hybrid transforms)
- **C** — Hybrid-generated payloads (deterministic transforms; no adaptive controller)
- **D** — Hybrid-generated payloads with **offline** adaptive strategy selection

**Derived trial fields:** :func:`prepare_trial_dataframe` sets ``code_changed`` when
baseline and trial status codes are both known and differ, and ``useful_signal``
when ``code_changed`` or ``is_abnormal`` holds. The latter is a **harness-defined**
interesting-response flag (or a rule applied at import time); it need not coincide
with ``code_changed`` alone.

**Aggregated metrics** (:func:`aggregate_metrics_by_group`) summarize each arm for
tables and plots: response-change rates quantify HTTP divergence from baseline;
``abnormal_rate`` reflects explicit flags; ``avg_abs_length_delta`` measures body
size drift; ``duplicate_candidate_rate`` captures payload diversity within an arm;
``requests_per_useful_signal`` is trials per ``useful_signal`` (``NaN`` when none,
to avoid silent division by zero in thesis tables).

Outputs a chart-friendly table (one row per experimental arm) at
``results/comparison_metrics.csv`` by default.

This module does **not** run Burp or send HTTP; inputs are **files or in-memory tables**
you produced (e.g. Intruder exports) or trial rows from offline replay.

For the **six-step manual operator workflow** (request JSON → generate → Intruder →
attack → export → analyze) and thin wrappers, see :mod:`burp_bridge`.

---------------------------------------------------------------------------
**Notebook / script workflow (saved Intruder export → comparison CSV)**

1. After a **manual** Intruder run, save or copy the results table (columns often
   named ``Payload``, ``Status``, ``Length`` — wording varies by Burp version).
2. For **one baseline HTTP context** fuzzed with many payloads, pass the **same**
   ``baseline_status_code`` and ``baseline_response_length`` (from a normal request)
   into :func:`burp_intruder_to_prepared_dataframe` together with ``request_id`` and
   ``experiment_group`` (``A``/``B``/``C``/``D`` or full enum value).
3. Repeat for each arm, then :func:`concat_prepared_trial_frames` and
   :func:`aggregate_metrics_by_group` (or :func:`comparison_metrics_table`).
4. Save with :func:`save_comparison_metrics` (or one-shot :func:`run_full_comparison_and_save`)
   → ``results/comparison_metrics.csv``.
5. Mixed project exports: :func:`normalize_raw_results_dataframe` accepts near-schema tables
   or Burp-style headers; then concat and aggregate as above.
6. Optional: :func:`melt_metrics_for_plots` for Seaborn / Altair.

Example::

    from pathlib import Path
    from src.evaluation_pipeline import (
        read_burp_intruder_csv,
        burp_intruder_to_prepared_dataframe,
        concat_prepared_trial_frames,
        comparison_metrics_table,
        save_comparison_metrics,
    )

    b = read_burp_intruder_csv(Path("exports/intruder_B.csv"))
    pb = burp_intruder_to_prepared_dataframe(
        b,
        experiment_group="B",
        request_id="lab-login-post-01",
        baseline_status_code=200,
        baseline_response_length=4123,
    )
    c = read_burp_intruder_csv(Path("exports/intruder_C.csv"))
    pc = burp_intruder_to_prepared_dataframe(
        c, experiment_group="C", request_id="lab-login-post-01",
        baseline_status_code=200, baseline_response_length=4123,
    )
    metrics = comparison_metrics_table(concat_prepared_trial_frames([pb, pc]))
    save_comparison_metrics(metrics)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd

from .evaluation import ExperimentGroup, TrialRecord

# -----------------------------------------------------------------------------
# Common trial-log schema (CSV / DataFrame)
# -----------------------------------------------------------------------------

TRIAL_LOG_COLUMNS_DOC = """
Expected input columns (wide, one row per trial)
================================================

Required:
  experiment_group   Arm label; use :class:`ExperimentGroup` values, e.g.
                     ``A_baseline_burp``, or short keys A/B/C/D (see aliases).
  trial_id           Unique id within the run.
  request_id         Stable id for the HTTP context being fuzzed.

Response comparison (ints or empty):
  baseline_status_code, trial_status_code
  baseline_response_length, trial_response_length

Candidate / quality:
  candidate_value    Raw payload sent (optional if payload_sha256 set).
  payload_sha256     Optional 64-char hex; computed from candidate_value if missing.

Flags (0/1, bool, or true/false strings):
  is_abnormal        Your harness marks materially interesting responses.
  is_invalid_candidate  Validator rejected before/without execution.

Optional:
  lab_run_id, notes, extra JSON blobs are ignored by aggregation unless prefixed.
"""

# column names as constants (typo guards for report + charts)
COL_GROUP = "experiment_group"
COL_TRIAL_ID = "trial_id"
COL_REQUEST_ID = "request_id"
COL_BASELINE_STATUS = "baseline_status_code"
COL_TRIAL_STATUS = "trial_status_code"
COL_BASELINE_LEN = "baseline_response_length"
COL_TRIAL_LEN = "trial_response_length"
COL_CANDIDATE = "candidate_value"
COL_PAYLOAD_HASH = "payload_sha256"
COL_ABNORMAL = "is_abnormal"
COL_INVALID = "is_invalid_candidate"

# derived columns added by :func:`prepare_trial_dataframe`
COL_CODE_CHANGED = "code_changed"
COL_USEFUL = "useful_signal"

SHORT_GROUP_ALIASES: dict[str, str] = {
    "a": ExperimentGroup.BASELINE_BURP.value,
    "b": ExperimentGroup.STATIC_DATASET.value,
    "c": ExperimentGroup.GENERATED.value,
    "d": ExperimentGroup.GENERATED_ADAPTIVE.value,
}


def coerce_cell_to_str(value: Any) -> str:
    """
    Convert one table cell to ``str``; NaN/None/NaT → ``\"\"``.

    Burp/Excel exports often leave numeric cells as float; ``str.join`` then raises
    ``TypeError: expected str instance, float found`` if those values are not coerced.
    """
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    if isinstance(value, float) and np.isnan(value):
        return ""
    if isinstance(value, (np.floating, np.integer)):
        try:
            if pd.isna(value):
                return ""
        except (TypeError, ValueError):
            pass
        try:
            return str(int(value)) if isinstance(value, np.integer) else str(float(value))
        except (TypeError, ValueError, OverflowError):
            return str(value)
    return str(value)


def coerce_series_to_str(series: pd.Series) -> pd.Series:
    return series.map(coerce_cell_to_str)


def coerce_dataframe_cells_to_str(df: pd.DataFrame) -> pd.DataFrame:
    """Force every cell to string (post-Intruder-parse safety net)."""
    out = df.copy()
    for c in out.columns:
        out[c] = out[c].map(coerce_cell_to_str)
    return out

# Burp Intruder (and similar) export column header hints — substring / equality match only;
# this is not scanner automation; it helps parse human-saved tables.
_INTRUDER_PAYLOAD_HINTS: tuple[str, ...] = (
    "payload",
    "payloads",
    "grep",
    "input",
    "vector",
    "attack",
)
_INTRUDER_STATUS_HINTS: tuple[str, ...] = (
    "status",
    "http status",
    "response status",
    "resp. status",
    "status code",
)
_INTRUDER_LENGTH_HINTS: tuple[str, ...] = (
    "length",
    "resp. length",
    "response length",
    "body length",
    "size",
)


def _normalize_header(name: str) -> str:
    return " ".join(str(name).strip().lower().split())


def _match_column_by_hints(df: pd.DataFrame, hints: tuple[str, ...]) -> str | None:
    """Pick first CSV column whose normalized header matches any hint (substring)."""
    for col in df.columns:
        n = _normalize_header(str(col))
        if not n:
            continue
        for h in hints:
            h = h.strip().lower()
            if n == h or h in n or n in h:
                return str(col)
    return None


def resolve_burp_style_columns(
    df: pd.DataFrame,
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """
    Map canonical schema column names → **actual** column names present in ``df``.

    Keys are internal names: ``candidate_value``, ``trial_status_code``,
    ``trial_response_length``.  Values are labels as they appear in the CSV.
    Raises ``ValueError`` if a required mapping cannot be resolved (override or hint).
    """
    ovr = dict(overrides or {})
    need = {
        COL_CANDIDATE: ovr.get(COL_CANDIDATE) or _match_column_by_hints(df, _INTRUDER_PAYLOAD_HINTS),
        COL_TRIAL_STATUS: ovr.get(COL_TRIAL_STATUS) or _match_column_by_hints(df, _INTRUDER_STATUS_HINTS),
        COL_TRIAL_LEN: ovr.get(COL_TRIAL_LEN) or _match_column_by_hints(df, _INTRUDER_LENGTH_HINTS),
    }
    missing = [k for k, v in need.items() if not v]
    if missing:
        raise ValueError(
            f"Could not resolve columns {missing} from headers {list(df.columns)!r}. "
            "Pass column_overrides with canonical_name -> csv_header, e.g. "
            "{'candidate_value': 'Payload', 'trial_status_code': 'Status'}."
        )
    return {k: str(v) for k, v in need.items()}


_TRIAL_CSV_DECODE_ORDER: tuple[str, ...] = ("utf-8-sig", "utf-8", "cp1252", "latin-1")


def read_burp_intruder_csv(path: str | Path, **read_csv_kw: Any) -> pd.DataFrame:
    """
    Read a Burp-exported CSV with UTF-8 BOM tolerance (common on Windows).

    Decodes **raw bytes** with a small encoding chain (preferred ``encoding`` first), then parses
    via :func:`pandas.read_csv` on a buffer so the C engine never opens the path as UTF-8.
    Extra kwargs are forwarded to :func:`pandas.read_csv` (except ``encoding``).
    """
    path = Path(path)
    kw = {"encoding": "utf-8-sig", **read_csv_kw}
    preferred = kw.pop("encoding", "utf-8-sig")
    chain: list[str] = []
    for e in (preferred, *_TRIAL_CSV_DECODE_ORDER):
        if e not in chain:
            chain.append(e)
    raw = path.read_bytes()
    text: str | None = None
    last_err: UnicodeDecodeError | None = None
    for enc in chain:
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError as e:
            last_err = e
            continue
    if text is None:
        assert last_err is not None
        raise last_err
    return pd.read_csv(StringIO(text), engine="python", **kw)


def burp_intruder_to_prepared_dataframe(
    df: pd.DataFrame,
    *,
    experiment_group: str | ExperimentGroup,
    request_id: str,
    baseline_status_code: int | None,
    baseline_response_length: int | None,
    trial_id_prefix: str = "trial",
    column_overrides: Mapping[str, str] | None = None,
    infer_abnormal_from_response: bool = False,
    abnormal_length_delta_threshold: float = 100.0,
) -> pd.DataFrame:
    """
    Turn a **single-context** Intruder result table into the common trial schema.

    **Baseline alignment:** ``baseline_*`` are broadcast to every row — the usual case
    where one normal response is compared against many fuzzed responses for the same
    insertion point.

    **Abnormal flag:** by default ``is_abnormal`` is False unless you pass a CSV column
    via overrides or set ``infer_abnormal_from_response=True`` (then status change or
    large length delta vs baseline marks abnormal).
    """
    cmap = resolve_burp_style_columns(df, column_overrides)
    out = pd.DataFrame()
    _cand_src = df[cmap[COL_CANDIDATE]]
    if isinstance(_cand_src, pd.DataFrame):
        _cand_src = _cand_src.iloc[:, 0]
    out[COL_CANDIDATE] = coerce_series_to_str(_cand_src)
    out[COL_TRIAL_STATUS] = pd.to_numeric(df[cmap[COL_TRIAL_STATUS]], errors="coerce")
    out[COL_TRIAL_LEN] = pd.to_numeric(df[cmap[COL_TRIAL_LEN]], errors="coerce")

    out[COL_GROUP] = canonical_experiment_group(experiment_group)
    out[COL_REQUEST_ID] = str(request_id)
    out[COL_TRIAL_ID] = [f"{trial_id_prefix}_{i}" for i in range(len(out))]

    out[COL_BASELINE_STATUS] = baseline_status_code
    out[COL_BASELINE_LEN] = baseline_response_length

    ovr_map = dict(column_overrides or {})
    inv_col = ovr_map.get(COL_INVALID)
    abn_col = ovr_map.get(COL_ABNORMAL)

    if inv_col and inv_col in df.columns:
        out[COL_INVALID] = _boolish(df[inv_col])
    else:
        out[COL_INVALID] = False

    if abn_col and abn_col in df.columns:
        out[COL_ABNORMAL] = _boolish(df[abn_col])
    else:
        out[COL_ABNORMAL] = False

    prepared = prepare_trial_dataframe(out)

    if infer_abnormal_from_response:
        bl = pd.to_numeric(prepared[COL_BASELINE_LEN], errors="coerce")
        tl = pd.to_numeric(prepared[COL_TRIAL_LEN], errors="coerce")
        delta = (tl - bl).abs()
        inferred = prepared[COL_CODE_CHANGED] | (delta > abnormal_length_delta_threshold)
        prepared[COL_ABNORMAL] = prepared[COL_ABNORMAL] | inferred
        prepared[COL_USEFUL] = prepared[COL_ABNORMAL] | prepared[COL_CODE_CHANGED]

    return prepared


def normalize_raw_results_dataframe(
    df: pd.DataFrame,
    *,
    experiment_group: str | ExperimentGroup,
    request_id: str,
    baseline_status_code: int | None = None,
    baseline_response_length: int | None = None,
    column_overrides: Mapping[str, str] | None = None,
    trial_id_prefix: str = "row",
    infer_abnormal_from_response: bool = False,
    abnormal_length_delta_threshold: float = 100.0,
) -> pd.DataFrame:
    """
    Normalize a raw table that is **already** close to the trial schema.

    If ``candidate_value``, ``trial_status_code``, and ``trial_response_length`` exist
    (any casing), they are renamed to canonical names.  Otherwise Burp-style hint
    matching is used (same as :func:`burp_intruder_to_prepared_dataframe`).

    Optional ``column_overrides``: map **canonical** name → **source** column name,
    e.g. ``{\"candidate_value\": \"Payload\", \"trial_status_code\": \"HTTP Code\"}``.
    """
    ovr = dict(column_overrides or {})
    lower_map = {_normalize_header(c): c for c in df.columns}

    def _pick(canonical: str, *aliases: str) -> str | None:
        if canonical in ovr:
            return ovr[canonical]
        for a in aliases:
            key = _normalize_header(a)
            if key in lower_map:
                return lower_map[key]
        return None

    src_cand = _pick(COL_CANDIDATE, "candidate_value", "payload", "payloads")
    src_stat = _pick(COL_TRIAL_STATUS, "trial_status_code", "status", "status code")
    src_len = _pick(COL_TRIAL_LEN, "trial_response_length", "length", "response length")
    src_bstat = _pick(COL_BASELINE_STATUS, "baseline_status_code", "baseline status")
    src_blen = _pick(COL_BASELINE_LEN, "baseline_response_length", "baseline length")

    if src_cand and src_stat and src_len:
        work = pd.DataFrame()

        def _one_col(s: str | None) -> pd.Series:
            if not s:
                return pd.Series(dtype=object)
            x = df[s]
            return x.iloc[:, 0] if isinstance(x, pd.DataFrame) else x

        work[COL_CANDIDATE] = coerce_series_to_str(_one_col(src_cand))
        work[COL_TRIAL_STATUS] = pd.to_numeric(_one_col(src_stat), errors="coerce")
        work[COL_TRIAL_LEN] = pd.to_numeric(_one_col(src_len), errors="coerce")
        if src_bstat:
            work[COL_BASELINE_STATUS] = pd.to_numeric(_one_col(src_bstat), errors="coerce")
        else:
            work[COL_BASELINE_STATUS] = baseline_status_code
        if src_blen:
            work[COL_BASELINE_LEN] = pd.to_numeric(_one_col(src_blen), errors="coerce")
        else:
            work[COL_BASELINE_LEN] = baseline_response_length
    else:
        return burp_intruder_to_prepared_dataframe(
            df,
            experiment_group=experiment_group,
            request_id=request_id,
            baseline_status_code=baseline_status_code,
            baseline_response_length=baseline_response_length,
            trial_id_prefix=trial_id_prefix,
            column_overrides=column_overrides,
            infer_abnormal_from_response=infer_abnormal_from_response,
            abnormal_length_delta_threshold=abnormal_length_delta_threshold,
        )

    work[COL_GROUP] = canonical_experiment_group(experiment_group)
    work[COL_REQUEST_ID] = str(request_id)
    work[COL_TRIAL_ID] = [f"{trial_id_prefix}_{i}" for i in range(len(work))]

    if COL_INVALID not in work.columns:
        ic = _pick(COL_INVALID, "is_invalid_candidate", "invalid")
        work[COL_INVALID] = _boolish(df[ic]) if ic else False
    if COL_ABNORMAL not in work.columns:
        ac = _pick(COL_ABNORMAL, "is_abnormal", "abnormal")
        work[COL_ABNORMAL] = _boolish(df[ac]) if ac else False

    prepared = prepare_trial_dataframe(work)
    if infer_abnormal_from_response:
        bl = pd.to_numeric(prepared[COL_BASELINE_LEN], errors="coerce")
        tl = pd.to_numeric(prepared[COL_TRIAL_LEN], errors="coerce")
        delta = (tl - bl).abs()
        inferred = prepared[COL_CODE_CHANGED] | (delta > abnormal_length_delta_threshold)
        prepared[COL_ABNORMAL] = prepared[COL_ABNORMAL] | inferred
        prepared[COL_USEFUL] = prepared[COL_ABNORMAL] | prepared[COL_CODE_CHANGED]
    return prepared


def concat_prepared_trial_frames(frames: list[pd.DataFrame]) -> pd.DataFrame:
    """Vertically stack prepared trial frames (e.g. one export per arm A–D)."""
    if not frames:
        return pd.DataFrame()
    return pd.concat([f for f in frames if f is not None and not f.empty], ignore_index=True)


def run_full_comparison_and_save(
    trials: pd.DataFrame | list[TrialRecord] | list[pd.DataFrame],
    *,
    output_path: str | Path | None = None,
    repo_root: Path | None = None,
) -> tuple[pd.DataFrame, Path]:
    """
    Aggregate → save ``comparison_metrics.csv`` → return ``(metrics_df, path)``.

    ``trials`` may be a single prepared DataFrame, a list of DataFrames (concatenated),
    or a list of :class:`TrialRecord`.
    """
    if isinstance(trials, list) and trials and isinstance(trials[0], pd.DataFrame):
        combined = concat_prepared_trial_frames(trials)
        metrics = comparison_metrics_table(combined)
    else:
        metrics = comparison_metrics_table(trials)  # type: ignore[arg-type]
    path = save_comparison_metrics(metrics, path=output_path, repo_root=repo_root)
    return metrics, path


def canonical_experiment_group(value: str | ExperimentGroup) -> str:
    """Normalize user-facing labels to :class:`ExperimentGroup` string values."""
    if isinstance(value, ExperimentGroup):
        return value.value
    s = str(value).strip()
    low = s.lower()
    if low in SHORT_GROUP_ALIASES:
        return SHORT_GROUP_ALIASES[low]
    for g in ExperimentGroup:
        if s == g.value or low == g.name.lower():
            return g.value
    if low in {g.value.lower() for g in ExperimentGroup}:
        for g in ExperimentGroup:
            if low == g.value.lower():
                return g.value
    return s


def _boolish(s: pd.Series) -> pd.Series:
    if s.dtype == bool:
        return s.astype(bool)
    return s.astype(str).str.lower().isin(("1", "true", "yes", "y"))


def _sha256_short(text: Any, n_bytes: int = 16) -> str:
    s = coerce_cell_to_str(text)
    h = hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()
    return h[: 2 * n_bytes]


def prepare_trial_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Validate core columns, normalize group labels, compute hashes and derived flags.

    Adds ``code_changed`` (strict status inequality vs baseline when both known),
    ``useful_signal`` (``is_abnormal`` OR ``code_changed``), and ``payload_sha256``
    when missing. ``is_abnormal`` must be supplied or merged in before aggregation
    if the thesis defines “interesting” beyond status change alone.
    """
    out = df.copy()
    # Align labels with CSV reality (spaces / BOM on headers) so COL_GROUP lookup matches.
    out.columns = [str(c).strip().lstrip("\ufeff").strip() for c in out.columns]
    if COL_GROUP not in out.columns:
        raise KeyError(f"Missing required column: {COL_GROUP}")

    out[COL_GROUP] = out[COL_GROUP].map(canonical_experiment_group)

    for col in (COL_ABNORMAL, COL_INVALID):
        if col not in out.columns:
            out[col] = False
        else:
            out[col] = _boolish(out[col])

    bs = pd.to_numeric(out.get(COL_BASELINE_STATUS), errors="coerce")
    ts = pd.to_numeric(out.get(COL_TRIAL_STATUS), errors="coerce")
    out[COL_CODE_CHANGED] = bs.notna() & ts.notna() & (bs != ts)

    out[COL_USEFUL] = out[COL_ABNORMAL] | out[COL_CODE_CHANGED]

    if COL_PAYLOAD_HASH not in out.columns:
        out[COL_PAYLOAD_HASH] = None
    if COL_CANDIDATE in out.columns:
        cand = coerce_series_to_str(out[COL_CANDIDATE])
        need = out[COL_PAYLOAD_HASH].isna() | (out[COL_PAYLOAD_HASH].astype(str).str.len() == 0)
        out.loc[need, COL_PAYLOAD_HASH] = cand.loc[need].map(_sha256_short)
    else:
        if out[COL_PAYLOAD_HASH].isna().all():
            out[COL_PAYLOAD_HASH] = out[COL_TRIAL_ID].astype(str).map(_sha256_short)

    return out


def load_trial_log_csv(path: str | Path, **read_csv_kw: Any) -> pd.DataFrame:
    """Load a trial log CSV and pass it through :func:`prepare_trial_dataframe`."""
    path = Path(path)
    kw = dict(read_csv_kw)
    preferred = kw.pop("encoding", "utf-8")
    chain: list[str] = []
    for e in (preferred, *_TRIAL_CSV_DECODE_ORDER):
        if e not in chain:
            chain.append(e)
    raw = path.read_bytes()
    text: str | None = None
    last_err: UnicodeDecodeError | None = None
    for enc in chain:
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError as e:
            last_err = e
            continue
    if text is None:
        assert last_err is not None
        raise last_err
    df = pd.read_csv(StringIO(text), engine="python", **kw)
    return prepare_trial_dataframe(df)


def trial_records_to_dataframe(records: list[TrialRecord]) -> pd.DataFrame:
    """
    Flatten in-memory :class:`TrialRecord` rows to the common trial schema.

    Pulls ``is_abnormal`` and ``is_invalid_candidate`` from ``record.tags`` when present.
    """
    rows: list[dict[str, Any]] = []
    for tr in records:
        tags = tr.tags or {}
        rows.append(
            {
                COL_GROUP: tr.group.value if isinstance(tr.group, ExperimentGroup) else str(tr.group),
                COL_TRIAL_ID: tr.trial_id,
                COL_REQUEST_ID: tr.request_context.request_id,
                COL_BASELINE_STATUS: tr.baseline_status_code,
                COL_TRIAL_STATUS: tr.trial_status_code,
                COL_BASELINE_LEN: tr.baseline_response_length,
                COL_TRIAL_LEN: tr.trial_response_length,
                COL_CANDIDATE: tr.candidate.value,
                COL_ABNORMAL: bool(tags.get("is_abnormal", False)),
                COL_INVALID: bool(tags.get("is_invalid_candidate", False)),
            }
        )
    return prepare_trial_dataframe(pd.DataFrame(rows))


# -----------------------------------------------------------------------------
# Aggregation metrics
# -----------------------------------------------------------------------------


def compute_length_delta_abs(row: pd.Series) -> float:
    bl = row.get(COL_BASELINE_LEN)
    tl = row.get(COL_TRIAL_LEN)
    try:
        if pd.isna(bl) or pd.isna(tl):
            return np.nan
        return float(abs(int(tl) - int(bl)))
    except (TypeError, ValueError):
        return np.nan


def aggregate_metrics_by_group(prepared: pd.DataFrame) -> pd.DataFrame:
    """
    One summary row per ``experiment_group`` for thesis tables and charts.

    Interpretation (reporting guidance)
    ------------------------------------
    **response_code_change_*** — Observable HTTP status shift versus the recorded
    baseline for the same ``request_id``; a coarse but objective signal in lab logs.

    **abnormal_*** — Depends on how ``is_abnormal`` was set when building the trial
    table (manual label or rule such as status/length thresholds); state that rule
    beside any chart.

    **avg_abs_length_delta** — Average magnitude of response body length change;
    complements status codes when errors return similar codes with different bodies.

    **useful_signal_count / requests_per_useful_signal** — ``useful_signal`` is true
    when either ``is_abnormal`` or ``code_changed``; the ratio measures how many
    fuzz attempts occur per such event (higher means sparser interesting outcomes).

    **invalid_candidate_rate** — Share of rows marked invalid before or without
    successful trial execution (pipeline or policy rejects).

    **duplicate_candidate_rate** — ``1 - unique(payload_sha256)/n`` within the arm;
    high values indicate repeated payloads (expected under small dictionaries, worth
    noting when comparing generators).

    **signal_efficiency** — Single 0–1 score for thesis summaries: ``0.5 × response_code_change_rate
    + 0.5 × (avg_abs_length_delta / max avg_abs_length_delta across arms in this table)``,
    with missing length deltas treated as 0 and an empty max treated as no length bonus.
    Higher means more status divergence and/or stronger relative body-size drift vs other arms.

    Column names
    ------------
    response_code_change_count / _rate
        Trials where baseline and trial status both exist and differ.
    abnormal_response_count / abnormal_rate
        Sum/mean of ``is_abnormal``.
    avg_abs_length_delta
        Mean absolute |trial_len - baseline_len| (NaN rows excluded).
    requests_per_useful_signal
        ``trial_count / useful_signal_count``; **NaN** if no useful signals
        (divide-by-zero avoided; report as n/a in prose).
    invalid_candidate_rate
        Mean of ``is_invalid_candidate``.
    duplicate_candidate_rate
        ``1 - unique(payload_sha256) / trial_count`` (within group).
    signal_efficiency
        Combined comparison score; see class docstring formula.
    """
    if prepared.empty:
        return pd.DataFrame()

    gcol = COL_GROUP
    pieces: list[pd.Series] = []

    for name, sub in prepared.groupby(gcol, sort=True):
        n = len(sub)
        code_chg = int(sub[COL_CODE_CHANGED].sum())
        abnormal_n = int(sub[COL_ABNORMAL].sum())
        useful_n = int(sub[COL_USEFUL].sum())
        invalid_rate = float(sub[COL_INVALID].mean()) if n else np.nan

        len_deltas = sub.apply(compute_length_delta_abs, axis=1)
        avg_len_delta = float(len_deltas.mean(skipna=True)) if len_deltas.notna().any() else np.nan

        uniq_payloads = sub[COL_PAYLOAD_HASH].nunique(dropna=True)
        dup_rate = float(1.0 - uniq_payloads / n) if n else np.nan

        rpus = float(n / useful_n) if useful_n > 0 else np.nan

        pieces.append(
            pd.Series(
                {
                    gcol: name,
                    "trial_count": n,
                    "response_code_change_count": code_chg,
                    "response_code_change_rate": code_chg / n if n else np.nan,
                    "abnormal_response_count": abnormal_n,
                    "abnormal_rate": abnormal_n / n if n else np.nan,
                    "avg_abs_length_delta": avg_len_delta,
                    "useful_signal_count": useful_n,
                    "requests_per_useful_signal": rpus,
                    "invalid_candidate_rate": invalid_rate,
                    "unique_candidate_count": int(uniq_payloads),
                    "duplicate_candidate_rate": dup_rate,
                },
                name=name,
            )
        )

    out = pd.DataFrame(pieces).reset_index(drop=True)
    out = _with_signal_efficiency(out)
    order = [g.value for g in ExperimentGroup]
    cat = pd.Categorical(out[gcol], categories=[x for x in order if x in set(out[gcol])], ordered=True)
    out[gcol] = cat
    return out.sort_values(gcol).reset_index(drop=True)


def _with_signal_efficiency(metrics: pd.DataFrame) -> pd.DataFrame:
    """
    Append ``signal_efficiency`` for each arm: half weight on HTTP status-change rate,
    half on average absolute length delta normalized to the strongest arm in *this* table.
    """
    if metrics.empty:
        return metrics
    out = metrics.copy()
    r = pd.to_numeric(out["response_code_change_rate"], errors="coerce").fillna(0.0).clip(0.0, 1.0)
    L = pd.to_numeric(out["avg_abs_length_delta"], errors="coerce").fillna(0.0)
    l_max = float(L.max())
    if not np.isfinite(l_max) or l_max <= 0:
        norm_l = pd.Series(0.0, index=out.index, dtype=float)
    else:
        norm_l = (L / l_max).clip(0.0, 1.0)
    out["signal_efficiency"] = 0.5 * r + 0.5 * norm_l
    return out


def comparison_metrics_table(
    trials: pd.DataFrame | list[TrialRecord],
) -> pd.DataFrame:
    """
    Run full pipeline: accept a DataFrame or list of :class:`TrialRecord`,
    return the comparison metrics table.
    """
    if isinstance(trials, list):
        df = trial_records_to_dataframe(trials)
    else:
        df = prepare_trial_dataframe(trials)
    return aggregate_metrics_by_group(df)


def save_comparison_metrics(
    metrics: pd.DataFrame,
    path: str | Path | None = None,
    repo_root: Path | None = None,
) -> Path:
    """Write metrics CSV; default ``<repo>/results/comparison_metrics.csv``."""
    root = repo_root or Path(__file__).resolve().parents[1]
    out_path = Path(path) if path else root / "results" / "comparison_metrics.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    metrics.to_csv(out_path, index=False)
    return out_path


def metrics_to_json_records(metrics: pd.DataFrame) -> list[dict[str, Any]]:
    """Safe for ``altair`` / ``plotly``: replace NaN with None."""
    def _nan_to_none(obj: Any) -> Any:
        if isinstance(obj, float) and (np.isnan(obj) or np.isinf(obj)):
            return None
        return obj

    records = metrics.to_dict(orient="records")
    return [{k: _nan_to_none(v) for k, v in row.items()} for row in records]


def melt_metrics_for_plots(
    metrics: pd.DataFrame,
    id_vars: tuple[str, ...] = (COL_GROUP, "trial_count"),
) -> pd.DataFrame:
    """
    Long-form table for Seaborn / Altair ``facet`` or shared y-axis charts.

    Keeps ``trial_count`` by default so normalized rates can be joined if needed.
    """
    cols = [c for c in id_vars if c in metrics.columns]
    return metrics.melt(id_vars=cols, var_name="metric", value_name="value")


@dataclass
class EvaluationRunConfig:
    """Optional metadata block (not written to metrics unless you merge manually)."""

    title: str = ""
    lab_target: str = ""
    notes: str = ""


__all__ = [
    "TRIAL_LOG_COLUMNS_DOC",
    "COL_GROUP",
    "COL_TRIAL_ID",
    "COL_REQUEST_ID",
    "COL_BASELINE_STATUS",
    "COL_TRIAL_STATUS",
    "COL_BASELINE_LEN",
    "COL_TRIAL_LEN",
    "COL_CANDIDATE",
    "COL_ABNORMAL",
    "COL_INVALID",
    "resolve_burp_style_columns",
    "read_burp_intruder_csv",
    "burp_intruder_to_prepared_dataframe",
    "normalize_raw_results_dataframe",
    "concat_prepared_trial_frames",
    "run_full_comparison_and_save",
    "canonical_experiment_group",
    "prepare_trial_dataframe",
    "load_trial_log_csv",
    "trial_records_to_dataframe",
    "aggregate_metrics_by_group",
    "comparison_metrics_table",
    "save_comparison_metrics",
    "metrics_to_json_records",
    "melt_metrics_for_plots",
    "EvaluationRunConfig",
]
