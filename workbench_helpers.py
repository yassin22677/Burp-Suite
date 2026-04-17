"""
Helpers for the manual Burp workbench (``app.py``): safe CSV reads, normalized-trial validation.

Section 3 lists only files under ``ui_workspace/results/`` whose names look like ``trials_*.csv``
(and are not blocklisted) **and** whose contents pass the normalized trial column schema.
"""

from __future__ import annotations

import hashlib
import io
import re
import time
from pathlib import Path
from typing import Any, Sequence

import pandas as pd

from src.evaluation_pipeline import coerce_cell_to_str

# Columns required for comparison_metrics_table / concat_prepared_trial_frames (wide trial log).
# Includes length fields required by :func:`prepare_trial_dataframe`.
NORMALIZED_TRIAL_REQUIRED_COLUMNS: frozenset[str] = frozenset(
    {
        "experiment_group",
        "trial_id",
        "request_id",
        "baseline_status_code",
        "trial_status_code",
        "baseline_response_length",
        "trial_response_length",
        "candidate_value",
    }
)

AGGREGATE_INVALID_SELECTION_MSG = (
    "Only normalized trial CSV files can be aggregated. Please normalize Burp exports first."
)
AGGREGATE_NO_SELECTION_MSG = "Select at least one normalized trial CSV (from Section 2)."
AGGREGATE_DUPLICATE_FILES_MSG = "Duplicate trial CSV paths in the aggregate selection. Each file must appear once."
AGGREGATE_DUPLICATE_BYTES_MSG = (
    "Two selected trial CSV files are byte-identical (duplicate input). Remove the duplicate from the aggregate selection."
)

AGGREGATE_WARNING_MESSAGES: frozenset[str] = frozenset(
    {
        AGGREGATE_INVALID_SELECTION_MSG,
        AGGREGATE_NO_SELECTION_MSG,
        AGGREGATE_DUPLICATE_FILES_MSG,
    }
)
NORMALIZED_TRIAL_SCHEMA_ERROR = "Invalid file: not a normalized trial CSV"

# Encodings to try for Windows exports, Excel, and Burp copy/paste quirks.
_READ_CSV_ENCODINGS: tuple[str, ...] = ("utf-8-sig", "utf-8", "cp1252", "latin-1")

# Step 2 saved output pattern (A–D arms) — used for downloads / strict naming elsewhere.
_NORMALIZED_TRIALS_OUTPUT_RE = re.compile(r"^trials_[ABCD]_.+\.csv$", re.IGNORECASE)

# Never treat these basenames as aggregate candidates even if they matched a loose pattern.
_AGGREGATE_FILENAME_BLOCKLIST = frozenset(
    {
        "b1.csv",
        "burp_results.csv",
        "comparison_metrics.csv",
        "trials_comparison_metrics.csv",
        "trials_burp_results.csv",
    }
)


def is_trials_aggregate_csv_filename(name: str) -> bool:
    """
    **Filename gate** for Section 3 (listing + aggregate): plain basename only; must start with
    ``trials_`` and end with ``.csv`` (case-insensitive); not blocklisted.

    This hides ``burp_results.csv``, ``b1.csv``, ``comparison_metrics.csv``, and any non-``trials_``
    CSV. A file must still pass :func:`is_normalized_trial_csv` (schema + readable parse) to appear
    in :func:`list_normalized_trial_csvs`.
    """
    raw = (name or "").strip()
    if not raw or raw != Path(raw).name:
        return False
    if ".." in raw:
        return False
    low = raw.lower()
    if low in _AGGREGATE_FILENAME_BLOCKLIST:
        return False
    return low.startswith("trials_") and low.endswith(".csv")


def is_normalized_trials_output_filename(name: str) -> bool:
    """
    True if basename matches Section 2 output pattern ``trials_<A|B|C|D>_….csv``.

    Raw Burp exports and unrelated CSVs typically fail this (and schema checks).
    """
    return bool(_NORMALIZED_TRIALS_OUTPUT_RE.match((name or "").strip()))


def safe_read_csv(path: Path) -> tuple[pd.DataFrame | None, str | None]:
    """
    Read a CSV with tolerant encoding. Returns ``(df, None)`` or ``(None, short_error)``.

    Decodes the file as bytes with utf-8-sig, utf-8, cp1252, latin-1 (in order), then parses
    with :func:`pandas.read_csv` on a Unicode buffer. This avoids pandas' C parser raising
    ``UnicodeDecodeError`` on some builds when the first encoding guess is wrong.
    """
    try:
        raw = path.read_bytes()
    except OSError as e:
        return None, f"Could not read file: {e}"

    if not raw.strip():
        return None, "The file is empty or not a CSV table."

    last_decode: str | None = None
    for enc in _READ_CSV_ENCODINGS:
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError as e:
            last_decode = str(e)
            continue
        try:
            df = pd.read_csv(io.StringIO(text), engine="python")
            return df, None
        except pd.errors.EmptyDataError:
            return None, "The file is empty or not a CSV table."
        except (pd.errors.ParserError, UnicodeDecodeError, TypeError, ValueError):
            continue

    if last_decode:
        return None, "File could not be read because of encoding or format issues."
    return None, "File could not be read because of encoding or format issues."


def normalize_trial_dataframe_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return a copy with column labels trimmed (whitespace + leading UTF-8 BOM in first name).

    CSV exports often carry spaces or a BOM on headers; validation used to accept those via
    stripped-name checks while :func:`pandas.DataFrame` keys stayed wrong, breaking aggregation
    with ``KeyError: experiment_group``.
    """
    out = df.copy()
    out.columns = [str(c).strip().lstrip("\ufeff").strip() for c in out.columns]
    return out


def is_normalized_trial_dataframe(df: pd.DataFrame) -> tuple[bool, str]:
    """
    Check that ``df`` has required normalized-trial columns (exact names on ``df.columns``).

    Callers should pass frames already passed through :func:`normalize_trial_dataframe_columns`.
    """
    cols = {str(c) for c in df.columns}
    missing = sorted(NORMALIZED_TRIAL_REQUIRED_COLUMNS - cols)
    if missing:
        return False, NORMALIZED_TRIAL_SCHEMA_ERROR
    if len(df.index) == 0:
        return False, NORMALIZED_TRIAL_SCHEMA_ERROR
    return True, ""


def read_validated_normalized_trial_csv(path: Path) -> tuple[pd.DataFrame | None, str | None]:
    """
    One read: encoding-tolerant CSV load + schema check for aggregate input.

    Returns ``(df, None)`` or ``(None, error_detail)``.
    """
    if not is_trials_aggregate_csv_filename(path.name):
        return None, NORMALIZED_TRIAL_SCHEMA_ERROR
    df, err = safe_read_csv(path)
    if err or df is None:
        return None, err or "Could not read file."
    df = normalize_trial_dataframe_columns(df)
    ok, reason = is_normalized_trial_dataframe(df)
    if not ok:
        return None, reason
    return df, None


def is_normalized_trial_csv(path: Path) -> tuple[bool, str]:
    """True if ``path`` is a readable normalized trial CSV (name pattern + required columns)."""
    df, err = read_validated_normalized_trial_csv(path)
    if df is None:
        return False, err or "Invalid file."
    return True, ""


def list_normalized_trial_csvs(results_dir: Path) -> list[str]:
    """
    Return sorted basenames of **valid normalized trial CSVs** under ``results_dir`` only
    (non-recursive). Wrong files never appear: each candidate must pass **both**

    #. :func:`is_trials_aggregate_csv_filename` — ``trials_*.csv``, not blocklisted, safe basename.
    #. :func:`is_normalized_trial_csv` — readable via :func:`safe_read_csv` and all columns in
       ``NORMALIZED_TRIAL_REQUIRED_COLUMNS``.

    Never deletes or renames files. Symlinks that resolve outside ``results_dir`` are skipped.
    """
    root = Path(results_dir).resolve()
    if not root.is_dir():
        return []
    names: list[str] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return []
    for p in entries:
        if not p.is_file():
            continue
        try:
            resolved = p.resolve()
        except OSError:
            continue
        if resolved.parent != root:
            continue
        if not is_trials_aggregate_csv_filename(p.name):
            continue
        try:
            ok, _ = is_normalized_trial_csv(p)
        except Exception:
            continue
        if ok:
            names.append(p.name)
    return names


def filter_aggregate_selection_to_allowed(
    posted_names: list[str],
    allowed_basenames: frozenset[str],
) -> list[str]:
    """
    Keep only basenames present in ``allowed_basenames`` (from :func:`list_normalized_trial_csvs`).
    Rejects path segments and tampered values; never raises.
    """
    out: list[str] = []
    seen: set[str] = set()
    for n in posted_names:
        s = (n or "").strip()
        if not s or "/" in s or "\\" in s or ".." in s:
            continue
        base = Path(s).name
        if base != s:
            continue
        if base not in allowed_basenames or base in seen:
            continue
        seen.add(base)
        out.append(base)
    return out


def friendly_aggregate_rejection(filename: str, technical_reason: str) -> str:
    """Map validation failure to a short UI string (no tracebacks)."""
    low = technical_reason.lower()
    if "encoding" in low or "decode" in low or "could not be read" in low or "parse" in low:
        return (
            f'"{filename}" could not be read because of encoding or format issues. '
            "Save the Burp table as UTF-8 CSV, or re-normalize from a fresh export."
        )
    return (
        f'"{filename}" is not a normalized trial CSV. Please use Section 2 to normalize '
        f"Burp results first. ({technical_reason})"
    )


def _format_normalize_parse_failure(diag: dict[str, Any], detail: str) -> str:
    cols = diag.get("column_names") or []
    col_part = f" Columns detected ({len(cols)}): {', '.join(str(c) for c in cols[:12])}" if cols else ""
    sep = diag.get("separator") or diag.get("parse_separator") or diag.get("separator_guess_from_header") or "unknown"
    enc = diag.get("encoding") or "unknown"
    fn = diag.get("input_file") or "(upload)"
    return (
        f"Could not read “{fn}” as an Intruder results table. Encoding: {enc}. Separator tried: {sep}.{col_part} "
        f"Expected: a CSV or plain-text table with a header row and one row per Intruder request (comma or tab), "
        f"including payload and HTTP status/length columns. {detail} "
        "Save or export the Intruder results table from Burp as a .csv file (UTF-8 if the save dialog offers it), "
        "then upload that file here. For standard CSV, set separator to comma or auto."
    )


def read_burp_intruder_export_tolerant(
    path: Path, sep: str
) -> tuple[pd.DataFrame | None, str | None, dict[str, Any]]:
    """
    Load a Burp Intruder export for Section 2.

    Returns ``(df, error_message, diagnostics)``. ``diagnostics`` always includes
    ``input_file``; on success adds ``encoding``, ``separator``, ``column_names``,
    ``row_count_parsed``, ``preview_rows``.
    """
    from src.burp_bridge import (
        _normalize_table_text,
        _parse_normalized_intruder_text,
        decode_export_bytes,
    )

    diag: dict[str, Any] = {"input_file": path.name, "separator_user": sep}
    try:
        raw = path.read_bytes()
    except OSError as e:
        return None, f"Could not read uploaded file: {e}", diag

    try:
        text, enc = decode_export_bytes(raw, "utf-8-sig")
    except UnicodeDecodeError:
        return (
            None,
            _format_normalize_parse_failure({**diag, "encoding": None}, "File is not valid UTF-8/UTF-16 text."),
            {**diag, "encoding": None, "column_names": []},
        )

    diag["encoding"] = enc
    normalized = _normalize_table_text(text)
    if not normalized.strip():
        return (
            None,
            _format_normalize_parse_failure({**diag, "column_names": []}, "No non-empty lines after cleanup."),
            {**diag, "column_names": []},
        )

    try:
        df, meta = _parse_normalized_intruder_text(normalized, sep)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as e:
        first = normalized.splitlines()[0] if normalized else ""
        guessed = None
        try:
            from src.burp_bridge import detect_intruder_separator

            guessed = detect_intruder_separator(first)
        except Exception:
            pass
        diag_fail = {**diag, "column_names": [], "first_line_preview": first[:200]}
        if guessed is not None:
            diag_fail["separator_guess_from_header"] = "tab" if guessed == "\t" else "comma"
        diag_fail["parse_encoding"] = diag.get("encoding")
        diag_fail["parse_separator"] = diag_fail.get("separator_guess_from_header") or "unknown"
        diag_fail["parse_columns"] = []
        diag_fail["parse_row_count"] = None
        return (
            None,
            _format_normalize_parse_failure(diag_fail, str(e) or "Parser could not build rows and columns."),
            diag_fail,
        )

    diag.update(meta)
    return df, None, diag


def hash_normalized_candidate_column(df: pd.DataFrame) -> str:
    """SHA-256 of newline-joined ``candidate_value`` (after column trim). Empty if column missing."""
    ndf = normalize_trial_dataframe_columns(df)
    if "candidate_value" not in ndf.columns:
        return ""
    cells = [coerce_cell_to_str(x) for x in ndf["candidate_value"].tolist()]
    joined = "\n".join(cells)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def normalize_cross_arm_duplicate_warnings(
    results_dir: Path,
    rid_fs: str,
    current_letter: str,
    new_candidate_sha: str,
) -> list[str]:
    """
    Detect duplicate **Intruder payload columns** across arms for the same ``request_id``.

    If ``trials_B_x.csv`` and ``trials_C_x.csv`` share the same candidate hash, metrics will
    lie; warn loudly after normalization.
    """
    if not new_candidate_sha:
        return []
    root = Path(results_dir).resolve()
    if not root.is_dir():
        return []
    warnings: list[str] = []
    for letter in "ABCD":
        if letter == current_letter:
            continue
        p = root / f"trials_{letter}_{rid_fs}.csv"
        if not p.is_file():
            continue
        df, err = safe_read_csv(p)
        if df is None or err:
            continue
        other_sha = hash_normalized_candidate_column(df)
        if other_sha == new_candidate_sha:
            warnings.append(
                f"Duplicate payloads vs arm {letter}: {p.name} has the same candidate_value hash as "
                "this export. Use a different Intruder payload list per arm."
            )
    return warnings


def aggregate_duplicate_file_bytes_errors(per_file: list[dict[str, Any]]) -> list[str]:
    """Fail aggregation when two **different basenames** are the same file bytes (copy-paste mistake)."""
    by_hash: dict[str, list[str]] = {}
    for row in per_file:
        fh = (row.get("file_sha256") or "").strip()
        name = row.get("file") or ""
        if not fh or not name:
            continue
        by_hash.setdefault(fh, []).append(name)
    out: list[str] = []
    for names in by_hash.values():
        if len(names) > 1:
            out.append(AGGREGATE_DUPLICATE_BYTES_MSG + f" ({', '.join(names)})")
    return out


def build_aggregate_input_report(paths: Sequence[Path], frames: Sequence[pd.DataFrame]) -> dict[str, Any]:
    """
    Per-file row counts, SHA-256 of file bytes and of ``candidate_value`` column.

    Emits **warnings** when two files with different ``experiment_group`` values share the same
    candidate-column hash (typical mistake: same Intruder run normalized as B and C).
    """
    warnings: list[str] = []
    per_file: list[dict[str, Any]] = []
    cand_rows: list[tuple[str, str, str]] = []
    for p, df in zip(paths, frames):
        ndf = normalize_trial_dataframe_columns(df)
        nrows = len(ndf.index)
        chash = ""
        if "candidate_value" in ndf.columns:
            cells = [coerce_cell_to_str(x) for x in ndf["candidate_value"].tolist()]
            joined = "\n".join(cells)
            chash = hashlib.sha256(joined.encode("utf-8")).hexdigest()
        try:
            fhash = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            fhash = ""
        gval = ""
        if "experiment_group" in ndf.columns:
            u = ndf["experiment_group"].astype(str).dropna().unique().tolist()
            if len(u) == 1:
                gval = str(u[0])
            elif len(u) == 0:
                gval = ""
            else:
                gval = "mixed"
                warnings.append(f"{p.name}: multiple experiment_group values in one file ({u!r}).")
        per_file.append(
            {
                "file": p.name,
                "rows": nrows,
                "experiment_group": gval,
                "candidate_column_sha256": chash,
                "file_sha256": fhash,
            }
        )
        cand_rows.append((p.name, gval, chash))

    by_cand: dict[str, list[tuple[str, str]]] = {}
    for name, g, ch in cand_rows:
        if not ch:
            continue
        by_cand.setdefault(ch, []).append((name, g))
    for _, lst in by_cand.items():
        groups = {g for _, g in lst if g and g != "mixed"}
        if len(lst) > 1 and len(groups) > 1:
            warnings.append(
                "Different experiment_group labels but identical candidate_value column hash — "
                f"files may be copies of the same Burp run: {[x[0] for x in lst]}."
            )

    pairwise_overlap: list[dict[str, Any]] = []
    name_sets: list[tuple[str, set[str]]] = []
    for p, df in zip(paths, frames):
        ndf = normalize_trial_dataframe_columns(df)
        if "candidate_value" not in ndf.columns:
            continue
        name_sets.append((Path(p).name, set(ndf["candidate_value"].astype(str))))
    for i in range(len(name_sets)):
        for j in range(i + 1, len(name_sets)):
            na, sa = name_sets[i]
            nb, sb = name_sets[j]
            den = max(len(sa), len(sb), 1)
            pairwise_overlap.append(
                {
                    "left_file": na,
                    "right_file": nb,
                    "overlap_rate": len(sa & sb) / den,
                    "left_distinct": len(sa),
                    "right_distinct": len(sb),
                }
            )

    return {"per_file": per_file, "warnings": warnings, "pairwise_candidate_overlap": pairwise_overlap}


def load_trial_frames_for_aggregate(
    results_dir: Path,
    filenames: list[str],
) -> tuple[list[pd.DataFrame] | None, str | None, dict[str, Any] | None]:
    """
    Resolve selected basenames under ``results_dir``, validate each, return DataFrames or one error string.

    On success, the third tuple element is a diagnostics dict (row counts, hashes, warnings).
    Any invalid name, missing file, encoding/read failure, or schema mismatch yields a single
    user-facing message (no tracebacks, no Python exception text).
    """
    results_dir = Path(results_dir).resolve()
    if not results_dir.is_dir():
        return None, AGGREGATE_INVALID_SELECTION_MSG, None

    if not filenames:
        return None, AGGREGATE_NO_SELECTION_MSG, None

    any_invalid = False
    frames: list[pd.DataFrame] = []
    paths_out: list[Path] = []

    for name in filenames:
        if "/" in name or "\\" in name or ".." in name:
            any_invalid = True
            continue
        base = Path(name).name
        if not is_trials_aggregate_csv_filename(base):
            any_invalid = True
            continue
        p = (results_dir / base).resolve()
        if not p.is_file() or p.parent != results_dir:
            any_invalid = True
            continue
        try:
            df, err = read_validated_normalized_trial_csv(p)
        except (OSError, UnicodeError, pd.errors.ParserError, ValueError):
            any_invalid = True
            continue
        if df is None or err:
            any_invalid = True
            continue
        frames.append(df)
        paths_out.append(p)

    if any_invalid:
        return None, AGGREGATE_INVALID_SELECTION_MSG, None

    if not frames:
        return None, AGGREGATE_INVALID_SELECTION_MSG, None

    resolved = [x.resolve() for x in paths_out]
    if len(resolved) != len(set(resolved)):
        return None, AGGREGATE_DUPLICATE_FILES_MSG, None

    report = build_aggregate_input_report(paths_out, frames)
    dup_bytes = aggregate_duplicate_file_bytes_errors(report.get("per_file", []))
    if dup_bytes:
        return None, dup_bytes[0], None
    return frames, None, report


def validate_baseline_for_normalize(status: int, length: int) -> tuple[bool, str | None]:
    """
    Reject missing or suspicious baseline fields before normalization.

    Returns ``(True, None)`` or ``(False, user_facing_message)``.
    """
    if status < 100 or status > 599:
        return False, "baseline_status should be a normal HTTP status code (100–599), e.g. 200."
    if length < 0:
        return False, "baseline_length cannot be negative."
    if length == 0:
        return (
            False,
            "baseline_length is 0 — enter the response length from a normal baseline request "
            "(Burp Intruder length column or similar), not zero.",
        )
    return True, None


def save_uploaded_burp_export(file_storage: Any, uploads_dir: Path) -> Path:
    """
    Save a Werkzeug ``FileStorage`` from Section 2 into ``uploads_dir``.

    Returns the absolute path written. Raises ``ValueError`` if no file.
    """
    from werkzeug.utils import secure_filename

    if file_storage is None or not getattr(file_storage, "filename", None):
        raise ValueError("No file uploaded.")
    uploads_dir = Path(uploads_dir)
    uploads_dir.mkdir(parents=True, exist_ok=True)
    name = f"{int(time.time())}_{secure_filename(file_storage.filename)}"
    path = uploads_dir / name
    file_storage.save(str(path))
    return path


def experiment_group_letter(group: str) -> str | None:
    """Return ``A``–``D`` from form value, or ``None`` if invalid."""
    g = (group or "").strip().upper()[:1]
    return g if g in "ABCD" else None


def path_request_json(requests_dir: Path, rid_fs: str) -> Path:
    return Path(requests_dir) / f"{rid_fs}.json"


def paths_generated_payloads(results_dir: Path, rid_fs: str) -> tuple[Path, Path]:
    """``(payloads.txt, meta.csv)`` for ``<rid_fs>_generated.*``."""
    r = Path(results_dir)
    return (r / f"{rid_fs}_generated.txt", r / f"{rid_fs}_generated_meta.csv")


def path_normalized_trial_csv(results_dir: Path, group_letter: str, rid_fs: str) -> Path:
    """``trials_<letter>_<rid_fs>.csv`` under ``results_dir``."""
    return Path(results_dir) / f"trials_{group_letter}_{rid_fs}.csv"


def paths_arm_payload_outputs(results_dir: Path, rid_fs: str, arm: str) -> tuple[Path, Path, Path]:
    """
    Step-1 output triple: (intruder ``.txt``, audit/meta ``.csv``, debug ``.json``).

    Arms **A** / **D** use ``*_armA.txt`` / ``*_armD.txt``. Arm **B** uses ``*_armB_static*``.
    Arm **C** uses ``*_armC_generated*`` (pipeline).
    """
    r = Path(results_dir)
    a = (arm or "").strip().upper()
    if a == "A":
        return (
            r / f"{rid_fs}_armA.txt",
            r / f"{rid_fs}_armA_audit.csv",
            r / f"{rid_fs}_armA_debug.json",
        )
    if a == "B":
        return (
            r / f"{rid_fs}_armB_static.txt",
            r / f"{rid_fs}_armB_static_audit.csv",
            r / f"{rid_fs}_armB_debug.json",
        )
    if a == "D":
        return (
            r / f"{rid_fs}_armD.txt",
            r / f"{rid_fs}_armD_meta.csv",
            r / f"{rid_fs}_armD_debug.json",
        )
    return (
        r / f"{rid_fs}_armC_generated.txt",
        r / f"{rid_fs}_armC_generated_meta.csv",
        r / f"{rid_fs}_armC_debug.json",
    )


def duplicate_payload_list_errors_vs_sibling_arms(
    results_dir: Path,
    rid_fs: str,
    current_arm: str,
    proposed_lines: list[str],
) -> list[str]:
    """
    If another arm's Intruder ``.txt`` already on disk has the **same** ordered payload hash
    as ``proposed_lines``, return user-facing error strings (empty if OK).

    Uses :func:`src.lab_arms.sha256_payload_lines` (UTF-8 newline-joined).
    """
    from src.lab_arms import sha256_payload_lines

    h = sha256_payload_lines(proposed_lines)
    errs: list[str] = []
    for letter in ("A", "B", "C", "D"):
        if letter == (current_arm or "").strip().upper()[:1]:
            continue
        p = paths_arm_payload_outputs(results_dir, rid_fs, letter)[0]
        if not p.is_file():
            continue
        other = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if sha256_payload_lines(other) == h:
            errs.append(
                f"Payload list is identical to the existing arm {letter} file ({p.name}). "
                "Use a different request_id, change parameters, or remove the conflicting file."
            )
    return errs


def unlink_arm_payload_outputs(paths: tuple[Path, Path, Path]) -> None:
    """Best-effort delete of the three Step-1 artifacts (txt, csv, json)."""
    for p in paths:
        try:
            if p.is_file():
                p.unlink()
        except OSError:
            pass


def format_user_facing_error(exc: BaseException, *, max_len: int = 320) -> str:
    """Single short message for the UI (no traceback)."""
    msg = (str(exc) or type(exc).__name__).strip()
    low = msg.lower()
    if "traceback" in low or 'file "' in low:
        return "Something went wrong. Check the server log for details."
    if len(msg) > max_len:
        msg = msg[: max_len - 3] + "..."
    return msg


def is_allowed_results_download(name: str) -> bool:
    """Basenames safe to serve from ``ui_workspace/results/`` via download route."""
    base = Path(name).name
    if base != name or ".." in base or "/" in base or "\\" in base:
        return False
    if base == "comparison_metrics.csv":
        return True
    if base.endswith("_generated.txt") or base.endswith("_generated_meta.csv"):
        return True
    if (
        base.endswith("_armA.txt")
        or base.endswith("_armA_audit.csv")
        or base.endswith("_armA_debug.json")
    ):
        return True
    if base.endswith("_armB_static.txt") or base.endswith("_armB_static_audit.csv") or base.endswith("_armB_debug.json"):
        return True
    if (
        base.endswith("_armC_generated.txt")
        or base.endswith("_armC_generated_meta.csv")
        or base.endswith("_armC_debug.json")
    ):
        return True
    if (
        base.endswith("_armD.txt")
        or base.endswith("_armD_meta.csv")
        or base.endswith("_armD_debug.json")
    ):
        return True
    if is_trials_aggregate_csv_filename(base):
        return True
    return False
