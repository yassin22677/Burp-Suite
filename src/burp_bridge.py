"""
Burp Suite interoperability bridge (**authorized lab workflows only**).

This module does **not** drive Burp programmatically. It formalizes **file-based**
hand-offs that match :class:`~context_extractor.RequestContextExtractor` and
:mod:`evaluation_pipeline` so operators have one place to read the workflow and
one API for conversions.

MANUAL WORKFLOW (operator, offline Python)
==========================================

This is the **canonical** evaluation path for real lab work. Optional in-process
``ExperimentRunner`` demos use fixture outcomes only and do not replace these steps.

1. **Export or describe one request from Burp as JSON** — Burp has no single
   “export RequestContext JSON” button; you manually record fields your thesis needs.
   Save UTF-8 JSON with at least ``url`` (or ``host`` + ``path``) and ``method``,
   plus a stable ``request_id`` reused across arms A–D. Mark the fuzz slot using
   ``parameters`` (see :class:`~context_extractor.RequestContextExtractor`).
   Use :func:`write_example_request_context_template` or ``burp_bridge.py template``
   for a starter file.

2. **Run** ``scripts/generate_payload_batch.py`` **with that request JSON** (and
   ``--family``, ``--kb``, ``-o`` for the Intruder payload list).

3. **Load the output text file into Burp Intruder** (one payload per line).

4. **Run the attack in Burp manually.**

5. **Export Burp results** (CSV/TSV as your Burp version allows).

6. **Run** ``scripts/normalize_burp_results.py``, **then**
   ``scripts/aggregate_comparison_metrics.py`` (or the equivalent
   :mod:`evaluation_pipeline` helpers) to merge trial CSVs and write comparison metrics.

**In-process A–D (fixture replay):** ``python scripts/run_lab_experiment.py --demo`` runs
:class:`experiment_runner.ExperimentRunner` with the same offline outcome pattern (no Burp).

**Scope / safety:** No sockets to Burp, no extension automation from this module.
Optional Montoya/Java pieces live under ``burp-montoya-extension/`` separately.

See also
--------
- :mod:`execution_backend` — ``replay_outcomes_from_mapping_rows`` for outcome dicts.
- ``scripts/normalize_burp_results.py`` — CLI for Burp export → trial schema.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Any, Mapping, TextIO

import numpy as np
import pandas as pd

from .context_extractor import RequestContext, RequestContextExtractor
from .evaluation import ExperimentGroup, TrialRecord
from .evaluation_pipeline import (
    COL_ABNORMAL,
    COL_BASELINE_LEN,
    COL_BASELINE_STATUS,
    COL_CANDIDATE,
    COL_GROUP,
    COL_INVALID,
    COL_REQUEST_ID,
    COL_TRIAL_ID,
    COL_TRIAL_LEN,
    COL_TRIAL_STATUS,
    burp_intruder_to_prepared_dataframe,
    canonical_experiment_group,
    coerce_dataframe_cells_to_str,
    prepare_trial_dataframe,
)
from .payload_validator import PayloadCandidate

# ---------------------------------------------------------------------------
# Intruder table I/O (shared with scripts/normalize_burp_results.py)
# ---------------------------------------------------------------------------


def detect_intruder_separator(first_line: str) -> str:
    """
    Choose tab vs comma from the header line (Burp often copies tab-separated tables).

    Returns ``"\\t"`` or ``","``.
    """
    tabs = first_line.count("\t")
    commas = first_line.count(",")
    return "\t" if tabs > commas else ","


def decode_export_bytes(raw: bytes, encoding_hint: str = "utf-8-sig") -> tuple[str, str]:
    """
    Decode Burp export bytes (UTF-8, UTF-16 BOM, Windows encodings).

    Returns ``(text, encoding_label)`` for diagnostics (workbench UI / logs).
    """
    if raw.startswith(b"\xff\xfe") and len(raw) >= 2:
        return raw.decode("utf-16-le"), "utf-16-le"
    if raw.startswith(b"\xfe\xff") and len(raw) >= 2:
        return raw.decode("utf-16-be"), "utf-16-be"
    enc_chain: list[str] = []
    for e in (encoding_hint, "utf-8-sig", "utf-8", "cp1252", "latin-1"):
        if e not in enc_chain:
            enc_chain.append(e)
    last: UnicodeDecodeError | None = None
    for enc in enc_chain:
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError as e:
            last = e
            continue
    assert last is not None
    raise last


def _normalize_table_text(text: str) -> str:
    """Drop leading/trailing blank lines; skip Excel ``sep=`` header row."""
    lines = text.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return ""
    if lines[0].strip().lower().startswith("sep="):
        lines = lines[1:]
    return "\n".join(lines)


def _intruder_sep_candidates(sep: str, first_line: str) -> list[str]:
    """Order of delimiters to try (Burp is usually tab; Excel may use comma or semicolon)."""
    if sep == "auto":
        preferred = detect_intruder_separator(first_line)
        out = [preferred]
        for c in ("\t", ",", ";"):
            if c not in out:
                out.append(c)
        return out
    if sep == "tab":
        return ["\t", ",", ";"]
    if sep == "comma":
        return [",", "\t", ";"]
    raise ValueError(f"sep must be auto|tab|comma, got {sep!r}")


def _read_csv_one(text: str, sep_char: str, *, skip_bad_lines: bool) -> pd.DataFrame:
    kw: dict[str, Any] = {"sep": sep_char, "engine": "python", "dtype": str}
    if skip_bad_lines:
        kw["on_bad_lines"] = "skip"
    try:
        return pd.read_csv(StringIO(text), **kw)
    except TypeError:
        # pandas < 1.3: no on_bad_lines
        kw.pop("on_bad_lines", None)
        return pd.read_csv(StringIO(text), **kw)


def _parse_loose_tsv(text: str) -> pd.DataFrame | None:
    """
    Last-resort tab parse when pandas fails (ragged rows: extra ``\\t`` inside a field).

    If a row has more than ``len(header)`` cells, extras are folded into the last column.
    """
    lines = [ln.rstrip("\r") for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    header = lines[0].split("\t")
    n = len(header)
    if n < 2:
        return None
    rows: list[list[str]] = []
    for ln in lines[1:]:
        parts = ln.split("\t")
        if len(parts) == n:
            rows.append(parts)
        elif len(parts) > n:
            rows.append(parts[: n - 1] + ["\t".join(parts[n - 1 :])])
        else:
            rows.append(parts + [""] * (n - len(parts)))
    return pd.DataFrame(rows, columns=header)


def _separator_label(sep_char: str) -> str:
    if sep_char == "\t":
        return "tab"
    if sep_char == ";":
        return "semicolon"
    if sep_char == ",":
        return "comma"
    return repr(sep_char)


def _parse_normalized_intruder_text(normalized: str, sep: str) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Parse already-normalized text; coerce all cells to str; return parse metadata for the UI.
    """
    if not normalized.strip():
        raise pd.errors.EmptyDataError("No rows after normalizing export text.")
    first_line = normalized.splitlines()[0] if normalized else ""
    candidates = _intruder_sep_candidates(sep, first_line)
    last_err: Exception | None = None
    for sep_char in candidates:
        for skip_bad in (False, True):
            try:
                df = _read_csv_one(normalized, sep_char, skip_bad_lines=skip_bad)
            except (pd.errors.ParserError, pd.errors.EmptyDataError) as e:
                last_err = e
                continue
            if df is None or df.empty:
                last_err = last_err or pd.errors.EmptyDataError("empty")
                continue
            if df.shape[1] >= 2 and len(df) >= 1:
                meta = {
                    "separator": _separator_label(sep_char),
                    "separator_char": sep_char,
                    "column_names": [str(c) for c in df.columns],
                    "row_count_parsed": int(len(df)),
                    "skipped_bad_lines": skip_bad,
                    "preview_rows": _preview_rows_for_diag(df, max_rows=3, max_cols=8),
                }
                return coerce_dataframe_cells_to_str(df), meta
            if df.shape[1] == 1 and len(df) >= 1:
                last_err = pd.errors.ParserError("Only one column; likely wrong separator.")
                continue
    loose = _parse_loose_tsv(normalized)
    if loose is not None and not loose.empty and loose.shape[1] >= 2:
        df2 = coerce_dataframe_cells_to_str(loose)
        meta = {
            "separator": "tab (loose)",
            "separator_char": "\t",
            "column_names": [str(c) for c in df2.columns],
            "row_count_parsed": int(len(df2)),
            "skipped_bad_lines": False,
            "preview_rows": _preview_rows_for_diag(df2, max_rows=3, max_cols=8),
        }
        return df2, meta
    if last_err is not None:
        raise last_err
    raise pd.errors.ParserError("Could not parse Intruder export as a table.")


def _preview_rows_for_diag(df: pd.DataFrame, *, max_rows: int, max_cols: int) -> list[list[str]]:
    out: list[list[str]] = []
    take = df.iloc[:max_rows, :max_cols]
    for _, row in take.iterrows():
        out.append([str(row.iloc[i]) if i < len(row) else "" for i in range(len(row))])
    return out


def parse_intruder_table_text(text: str, *, sep: str = "auto") -> pd.DataFrame:
    """
    Parse Burp Intruder-style table text with several fallbacks.

    Tries multiple delimiters, optional ``on_bad_lines='skip'``, then a loose TSV merge
    when rows have more tab splits than the header (common when copying from Burp).
    """
    normalized = _normalize_table_text(text)
    df, _meta = _parse_normalized_intruder_text(normalized, sep)
    return df


def read_burp_intruder_export(
    path: str | Path,
    *,
    sep: str = "auto",
    encoding: str = "utf-8-sig",
) -> pd.DataFrame:
    """
    Load a Burp Intruder results export from disk.

    ``sep``:
        - ``"auto"`` — try tab, comma, semicolon (after sniffing the header line).
        - ``"tab"`` / ``"comma"`` — prefer that delimiter, then fall back to others.

    Decoding handles UTF-8/UTF-16 BOM, cp1252, and latin-1. Parsing retries with
    ``on_bad_lines='skip'`` when available, then a loose tab merge for ragged Burp copies.
    """
    path = Path(path)
    raw = path.read_bytes()
    text, _enc = decode_export_bytes(raw, encoding)
    return parse_intruder_table_text(text, sep=sep)


def read_burp_intruder_export_text(
    text: str,
    *,
    sep: str = "auto",
) -> pd.DataFrame:
    """Parse Intruder-style text (e.g. pasted TSV) without touching the filesystem."""
    return parse_intruder_table_text(text, sep=sep)


def read_burp_intruder_export_fileobj(
    fileobj: TextIO,
    *,
    sep: str = "auto",
) -> pd.DataFrame:
    """Parse from a text stream (tests); reads the full stream into memory."""
    return read_burp_intruder_export_text(fileobj.read(), sep=sep)


# ---------------------------------------------------------------------------
# Request context JSON ↔ :class:`RequestContext`
# ---------------------------------------------------------------------------


def load_request_context_json(path: str | Path) -> dict[str, Any]:
    """Load a JSON object from ``path`` (UTF-8)."""
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise TypeError(f"Expected JSON object at root, got {type(data).__name__}")
    return data


def save_request_context_json(path: str | Path, payload: Mapping[str, Any]) -> None:
    """Write ``payload`` as indented UTF-8 JSON (stable for version control)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(dict(payload), f, indent=2, ensure_ascii=False)
        f.write("\n")


def extract_request_context(raw: Mapping[str, Any]) -> RequestContext:
    """Parse a mapping with :class:`~context_extractor.RequestContextExtractor`."""
    return RequestContextExtractor().extract(raw)


def request_context_to_json_dict(ctx: RequestContext) -> dict[str, Any]:
    """
    Serialize :class:`~context_extractor.RequestContext` to JSON-friendly dict.

    Round-tripping through :func:`extract_request_context` preserves semantics;
    field order may differ (parameters are sorted in the extractor).
    """
    return {
        "request_id": ctx.request_id,
        "method": ctx.method,
        "url": ctx.url,
        "path": ctx.path,
        "content_type": ctx.content_type,
        "raw_excerpt": ctx.raw_excerpt,
        "parameters": [
            {
                "name": t.name,
                "location": t.location.value,
                "declared_type": t.declared_type,
                "encoding_notes": list(t.encoding_notes),
            }
            for t in ctx.parameter_tags
        ],
        "extension_blobs": dict(ctx.extension_blobs),
    }


EXAMPLE_REQUEST_CONTEXT_TEMPLATE: dict[str, Any] = {
    "request_id": "lab_replace_with_stable_id",
    "method": "POST",
    "url": "https://lab.example/api/search",
    "content_type": "application/json",
    "parameters": [
        {
            "name": "q",
            "location": "json",
            "declared_type": "string",
            "encoding_notes": ["Mark the Intruder payload position for this field."],
        }
    ],
    "extension_blobs": {
        "burp_note": "Optional: paste non-JSON metadata here; keep JSON-serializable values.",
    },
}


def write_example_request_context_template(path: str | Path) -> None:
    """Write :data:`EXAMPLE_REQUEST_CONTEXT_TEMPLATE` for operators to edit."""
    save_request_context_json(path, EXAMPLE_REQUEST_CONTEXT_TEMPLATE)


# ---------------------------------------------------------------------------
# Intruder → evaluation schema → :class:`TrialRecord` / replay outcomes
# ---------------------------------------------------------------------------


def intruder_export_to_prepared_trials(
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
    Burp Intruder table → canonical trial columns + derived flags.

    Wraps :func:`evaluation_pipeline.burp_intruder_to_prepared_dataframe` and
    :func:`evaluation_pipeline.prepare_trial_dataframe`.
    """
    prepared = burp_intruder_to_prepared_dataframe(
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
    return prepare_trial_dataframe(prepared)


def _experiment_group_from_row(value: Any) -> ExperimentGroup:
    canon = canonical_experiment_group(str(value))
    for g in ExperimentGroup:
        if g.value == canon:
            return g
    raise ValueError(f"Unknown experiment_group label: {value!r} (canonical={canon!r})")


def _int_or_none(x: Any) -> int | None:
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return None
    if isinstance(x, str) and not str(x).strip():
        return None
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return None


def prepared_trial_row_to_replay_outcome(row: Mapping[str, Any]) -> dict[str, Any]:
    """
    One prepared trial row → outcome dict for :class:`~execution_backend.OfflineReplayExecutionBackend`.

    Keys align with :func:`execution_backend.replay_outcomes_from_mapping_rows`.
    """
    r = dict(row)
    out: dict[str, Any] = {
        "trial_status_code": _int_or_none(r.get(COL_TRIAL_STATUS)),
        "trial_response_length": _int_or_none(r.get(COL_TRIAL_LEN)),
        "is_abnormal": bool(r.get(COL_ABNORMAL, False)),
        "is_invalid_candidate": bool(r.get(COL_INVALID, False)),
    }
    if r.get("strong_abnormal") is not None:
        out["strong_abnormal"] = bool(r["strong_abnormal"])
    if r.get("moderate_differential") is not None:
        out["moderate_differential"] = bool(r["moderate_differential"])
    return out


def prepared_trials_to_trial_records(
    prepared: pd.DataFrame,
    request_context: RequestContext,
) -> list[TrialRecord]:
    """
    Prepared trial DataFrame (one context) → in-memory :class:`TrialRecord` list.

    ``prepared`` must include canonical columns from :mod:`evaluation_pipeline`.
    All rows are assumed to belong to ``request_context`` (same Intruder run).
    """
    required = (
        COL_GROUP,
        COL_TRIAL_ID,
        COL_CANDIDATE,
        COL_TRIAL_STATUS,
        COL_TRIAL_LEN,
    )
    for c in required:
        if c not in prepared.columns:
            raise KeyError(f"prepared trials missing column {c!r}")

    records: list[TrialRecord] = []
    for _, row in prepared.iterrows():
        group = _experiment_group_from_row(row[COL_GROUP])
        tags: dict[str, Any] = {
            "is_abnormal": bool(row.get(COL_ABNORMAL, False)),
            "is_invalid_candidate": bool(row.get(COL_INVALID, False)),
            "import_source": "burp_intruder",
        }
        cand = PayloadCandidate(
            value=str(row[COL_CANDIDATE]),
            source_label="burp_intruder",
            experiment_group=group.value,
            extra={
                "trial_id": str(row[COL_TRIAL_ID]),
                "request_id": str(row.get(COL_REQUEST_ID, request_context.request_id)),
            },
        )
        records.append(
            TrialRecord(
                trial_id=str(row[COL_TRIAL_ID]),
                group=group,
                request_context=request_context,
                candidate=cand,
                baseline_status_code=_int_or_none(row.get(COL_BASELINE_STATUS)),
                baseline_response_length=_int_or_none(row.get(COL_BASELINE_LEN)),
                trial_status_code=_int_or_none(row.get(COL_TRIAL_STATUS)),
                trial_response_length=_int_or_none(row.get(COL_TRIAL_LEN)),
                tags=tags,
            )
        )
    return records


def prepared_trials_to_outcome_rows(prepared: pd.DataFrame) -> list[dict[str, Any]]:
    """Vectorized helper: each row → replay outcome dict (same order as rows)."""
    return [prepared_trial_row_to_replay_outcome(row) for _, row in prepared.iterrows()]
