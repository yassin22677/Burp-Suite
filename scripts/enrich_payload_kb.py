#!/usr/bin/env python3
"""
Build an enriched payload knowledge base from ``clean_payloads_only.csv``.

Design principles (thesis / report friendly)
---------------------------------------------
1. **Authoritative family** comes from the existing ``category`` column (your curated
   label). We normalize it to ``kb_family`` but do not overwrite it with guesses.

2. **Heuristic columns** only fire when regex / structural checks match. If no rule
   matches inside a family, we record ``unknown`` (never a bogus fine-grained label).

3. **Application / injection-point context** (which query parameter, JSON field, etc.)
   is **not** present in this CSV. Those columns are explicitly ``unknown`` with a
   short rationale column for the report.

Output: ``data/enriched_payloads.csv`` (all original columns plus derived ones).

Column semantics (high level)
-----------------------------
* ``kb_family``: normalized copy of your ``category`` label (authoritative).
* ``heuristic_pattern_band``: extra coarse signal from regex/structure inside that
  family; if nothing matches, value is ``unknown`` (never guessed sub-genres).
* ``application_injection_context``: always ``unknown`` here because the CSV does not
  record real parameters or insertion points—see ``application_context_unknown_reason``.

Usage::
    python scripts/enrich_payload_kb.py

Requires: pandas (already used elsewhere in this repository).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pandas as pd

from _repo_root import ensure_repo_on_path

REPO_ROOT = ensure_repo_on_path()
DEFAULT_INPUT = REPO_ROOT / "data" / "clean_payloads_only.csv"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "enriched_payloads.csv"

# -----------------------------------------------------------------------------
# Compiled patterns (conservative: prefer unknown over false precision)
# -----------------------------------------------------------------------------
RE_HTTP_TAIL = re.compile(r"\sHTTP/\d+\.\d+\s*$", re.IGNORECASE)
RE_TAIL_SNIPPET = re.compile(r"HTTP/\d+\.\d+", re.IGNORECASE)
RE_PCT_SEQ = re.compile(r"%[0-9A-Fa-f]{2}")
RE_DOUBLE_PCT = re.compile(r"%25[0-9A-Fa-f]{2}", re.IGNORECASE)
RE_CRLF_ENCODED = re.compile(r"%0[dD](%0[aA])?%0[dD](%0[aA])?", re.IGNORECASE)
RE_CRLF_LITERAL = re.compile(r"[\r\n]")
RE_NULL_PCT = re.compile(r"%00", re.IGNORECASE)

# SQL-ish (loose tokens; validated only when row is sql family for "unknown")
RE_SQL_WAITFOR = re.compile(r"waitfor\s+delay", re.IGNORECASE)
RE_SQL_SLEEP = re.compile(r"\bsleep\s*\(", re.IGNORECASE)
RE_SQL_BENCHMARK = re.compile(r"\bbenchmark\s*\(", re.IGNORECASE)
RE_SQL_UNION = re.compile(r"\bunion\b.+\bselect\b", re.IGNORECASE | re.DOTALL)
RE_SQL_TAUTOLOGY = re.compile(
    r"('\s*or\s*'1'\s*=\s*'1')|('\s*and\s*'1'\s*=\s*'1')"
    r"|(\"\s*or\s*\"1\"\s*=\s*\"1\")|(\band\b\s*\"1\"\s*=\s*\"1\")",
    re.IGNORECASE,
)
RE_SQL_STACKED_END = re.compile(r";\s*(\-\-|#|/\*)", re.IGNORECASE)
RE_SQL_COMMENT_DD = re.compile(r"\-\-")
RE_SQL_SELECT = re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE | re.DOTALL)

# XSS-ish
RE_XSS_SCRIPT_TAG = re.compile(r"<\s*script\b", re.IGNORECASE)
RE_XSS_EVENT_HANDLER = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
RE_XSS_JS_URI = re.compile(r"javascript\s*:", re.IGNORECASE)

# Transport / header smuggling hints (encoding or literal CRLF)
RE_SET_COOKIE = re.compile(r"set-cookie\s*:", re.IGNORECASE)


def _normalize_family(category: str) -> str:
    c = (category or "").strip().lower().replace(" ", "_")
    return c or "unknown"


def _pipe_field_count(s: str) -> int:
    if not s:
        return 0
    # rough: pipes often separate form-log fields
    return s.count("|") + 1


def pct_density(s: str) -> float:
    if not s:
        return 0.0
    matches = RE_PCT_SEQ.findall(s)
    return len(matches) / max(len(s), 1)


def encoding_class(s: str) -> str:
    """
    Surface-level class only: we cannot infer charset or full double-encoding chains.
    """
    if not s:
        return "unknown"
    has_pct = bool(RE_PCT_SEQ.search(s))
    try:
        ascii_only = s.encode("ascii")
        _ = ascii_only  # noqa: F841
        if has_pct:
            return "ascii_with_percent_encoding"
        return "ascii_plain"
    except UnicodeEncodeError:
        if has_pct:
            return "mixed_unicode_with_percent_encoding"
        return "unicode_plain"


def sql_pattern_band(payload: str) -> str:
    """Return one coarse tag when evidence exists; else unknown."""
    if RE_SQL_WAITFOR.search(payload) or RE_SQL_SLEEP.search(payload) or RE_SQL_BENCHMARK.search(payload):
        return "time_based_or_delay_primitive"
    if RE_SQL_UNION.search(payload):
        return "union_select_evidence"
    if RE_SQL_TAUTOLOGY.search(payload):
        return "boolean_tautology_evidence"
    if RE_SQL_STACKED_END.search(payload) or (RE_SQL_COMMENT_DD.search(payload) and "'" in payload):
        return "stacked_or_comment_termination_evidence"
    if RE_SQL_SELECT.search(payload):
        return "select_from_evidence"
    return "unknown"


def xss_pattern_band(payload: str) -> str:
    if RE_XSS_SCRIPT_TAG.search(payload):
        return "script_tag_evidence"
    if RE_XSS_JS_URI.search(payload):
        return "javascript_uri_evidence"
    if RE_XSS_EVENT_HANDLER.search(payload):
        return "event_handler_evidence"
    if "%3cscript" in payload.lower() or "%3cscr" in payload.lower():
        return "percent_encoded_markup_evidence"
    return "unknown"


def cmd_injection_band(payload: str) -> str:
    """
    Very weak ground truth for generic \"cmd\" Family; many rows are benign logs.
    """
    low = payload.lower()
    if RE_CRLF_ENCODED.search(payload) or (
        RE_CRLF_LITERAL.search(payload) and RE_SET_COOKIE.search(payload)
    ):
        return "crlf_header_smuggling_evidence"
    if "set-cookie%3a" in low or "set-cookie:" in low:
        return "header_injection_token_evidence"
    if re.search(r"<!--\s*#exec", payload, re.IGNORECASE):
        return "ssi_exec_evidence"
    return "unknown"


def encoded_attack_band(payload: str) -> str:
    d = pct_density(payload)
    if d >= 0.03:
        return "high_percent_encoding_density"
    if RE_DOUBLE_PCT.search(payload):
        return "double_percent_sequence"
    if RE_CRLF_ENCODED.search(payload):
        return "crlf_percent_encoded"
    if "%3f" in payload.lower() or "%20" in payload.lower():
        return "trivial_encoded_token"
    return "unknown"


def heuristic_secondary_tag(kb_family: str, payload: str) -> str:
    """
    Single supplemental tag per row for quick filtering (still heuristic).
    For families without specific rules, not_applicable.
    """
    if kb_family == "sql":
        return sql_pattern_band(payload)
    if kb_family == "xss":
        return xss_pattern_band(payload)
    if kb_family == "cmd":
        return cmd_injection_band(payload)
    if kb_family == "encoded_attack":
        return encoded_attack_band(payload)
    if kb_family == "other":
        return "not_applicable"
    return "not_applicable"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2

    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.insert(0, "row_id", range(len(out)))

    p = out["payload"].astype(str)
    out["kb_family"] = out["category"].map(_normalize_family)

    # Structural
    out["char_len_computed"] = p.str.len()
    out["length_matches_computed"] = (out["char_len_computed"] == out["length"]).map(
        {True: "yes", False: "no"}
    )
    out["line_break_count"] = p.str.count(r"\r") + p.str.count(r"\n")
    out["pipe_field_count_approx"] = p.map(_pipe_field_count)
    out["space_ratio"] = (p.str.count(r" ") / out["char_len_computed"].replace(0, 1)).fillna(0.0)
    out["digit_ratio"] = (p.str.count(r"\d") / out["char_len_computed"].replace(0, 1)).fillna(0.0)
    out["unique_char_ratio"] = p.map(lambda s: len(set(s)) / max(len(s), 1))
    out["shannon_entropy_bits"] = p.map(shannon_entropy)

    # Capture / transport context (observable in string)
    out["has_http_version_tail"] = p.map(lambda s: bool(RE_HTTP_TAIL.search(s)))
    out["contains_http_version_token"] = p.map(lambda s: bool(RE_TAIL_SNIPPET.search(s)))
    out["field_delimiter_style"] = p.map(
        lambda s: "pipe_rich" if s.count("|") >= 3 else ("has_pipes" if "|" in s else "no_pipes")
    )
    out["quoted_csv_like_wrapping"] = p.str.startswith('"') & p.str.endswith('"')

    # True injection context is unknown from this file
    out["application_injection_context"] = "unknown"
    out["application_context_unknown_reason"] = (
        "Source CSV does not name HTTP parameters, body schema, or insertion offsets; "
        "strings appear to embed proxy/log capture (e.g. HTTP version tail) rather than "
        "a single injection-point view."
    )

    # Encoding labeling (surface)
    out["percent_escape_count"] = p.map(lambda s: len(RE_PCT_SEQ.findall(s)))
    out["percent_encoding_density"] = p.map(pct_density)
    out["encoding_surface_class"] = p.map(encoding_class)
    out["has_double_percent_encoding"] = p.map(lambda s: bool(RE_DOUBLE_PCT.search(s)))
    out["has_null_percent"] = p.map(lambda s: bool(RE_NULL_PCT.search(s)))
    out["has_crlf_encoded_or_literal"] = p.map(
        lambda s: bool(RE_CRLF_ENCODED.search(s) or RE_CRLF_LITERAL.search(s))
    )

    # Family-adjunct heuristics (never replace kb_family)
    out["heuristic_pattern_band"] = [
        heuristic_secondary_tag(fam, val) for fam, val in zip(out["kb_family"], p)
    ]

    # Consistency flags for the report (do not auto-relable)
    def _consistency_row(r: pd.Series) -> str:
        fam = r["kb_family"]
        band = r["heuristic_pattern_band"]
        if (
            fam in ("sql", "xss", "encoded_attack", "cmd")
            and band not in ("unknown", "not_applicable")
        ):
            return "pattern_supports_family"
        if fam in ("sql", "xss", "encoded_attack", "cmd") and band == "unknown":
            return "no_keyword_pattern_matched"
        if fam == "other":
            return "not_applicable"
        return "weak_or_generic_capture"

    out["label_consistency_flag"] = out.apply(_consistency_row, axis=1)

    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enrich clean_payloads_only.csv into a KB table.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"Input not found: {args.input}", file=sys.stderr)
        return 1

    df = pd.read_csv(args.input, dtype={"needs_review": str, "priority": str})
    enriched = enrich(df)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    enriched.to_csv(args.output, index=False)
    print(f"Wrote {len(enriched)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
