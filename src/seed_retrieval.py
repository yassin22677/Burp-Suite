"""
Deterministic seed scoring for retrieval (thesis-friendly, no external services).

Scores each enriched CSV row with a **fixed weighted sum** of interpretable terms in
``[0, 1]``.  Weights are documented constants; same inputs always yield the same
``total`` and ``breakdown`` dict.

**Terms (compatible with ``data/enriched_payloads.csv`` columns):**

1. **context_overlap** — fraction of path/parameter tokens appearing in the payload
   (lowercased substring match).  Captures coarse “this seed mentions the same
   resource shape as the request”.

2. **label_consistency** — maps ``label_consistency_flag`` to a numeric prior:
   ``pattern_supports_family`` > ``weak_or_generic_capture`` >
   ``no_keyword_pattern_matched`` > ``not_applicable``.

3. **heuristic_band_informativeness** — non-``unknown`` / non-``not_applicable``
   ``heuristic_pattern_band`` gets a fixed bonus scale (metadata is informative).

4. **encoding_alignment** — compares ``encoding_surface_class`` to
   ``RequestContext.content_type`` and primary ``ParameterLocation`` (e.g. JSON body
   prefers plain ASCII/unicode text; query-like contexts tolerate percent-encoding).

5. **percent_density_fit** — when the URL/path contains ``%`` or the target family is
   ``encoded_attack``, rows with higher ``percent_encoding_density`` score higher;
   otherwise uses a mild preference for moderate density.

6. **length_prior** — triangular preference around a target length (default 96 chars)
   using ``char_len_computed`` or ``length`` from the row.

Each term is clipped to ``[0, 1]``.  **Total** = ``sum(weight_i * term_i)`` with
weights summing to 1.0.
"""

from __future__ import annotations

import re
from typing import Mapping

from .context_extractor import ParameterLocation, RequestContext

# Weights (must sum to 1.0 for easy thesis explanation)
W_CONTEXT = 0.22
W_LABEL = 0.14
W_HEURISTIC_BAND = 0.14
W_ENCODING = 0.18
W_PERCENT = 0.16
W_LENGTH = 0.16
assert abs(W_CONTEXT + W_LABEL + W_HEURISTIC_BAND + W_ENCODING + W_PERCENT + W_LENGTH - 1.0) < 1e-6


def _context_keyword_set(ctx: RequestContext) -> set[str]:
    parts = re.split(r"/+", ctx.path.strip("/").replace("%20", " "))
    s = {p.lower() for p in parts if len(p) >= 2}
    for pm in ctx.parameter_tags:
        s.add(pm.name.lower())
    return {x for x in s if x}


def _term_context_overlap(payload: str, ctx: RequestContext) -> float:
    kws = _context_keyword_set(ctx)
    if not kws:
        return 0.35
    pl = payload.lower()
    hits = sum(1 for k in kws if k and k in pl)
    return min(1.0, hits / len(kws))


def _term_label_consistency(row: Mapping[str, str]) -> float:
    flag = (row.get("label_consistency_flag") or "").strip().lower()
    if flag == "pattern_supports_family":
        return 1.0
    if flag == "weak_or_generic_capture":
        return 0.55
    if flag == "no_keyword_pattern_matched":
        return 0.25
    if flag == "not_applicable":
        return 0.15
    return 0.4


def _term_heuristic_band(row: Mapping[str, str]) -> float:
    band = (row.get("heuristic_pattern_band") or "").strip().lower()
    if band in ("", "unknown"):
        return 0.2
    if band == "not_applicable":
        return 0.35
    return 1.0


def _term_encoding_alignment(row: Mapping[str, str], ctx: RequestContext) -> float:
    enc = (row.get("encoding_surface_class") or "").strip().lower()
    ct = (ctx.content_type or "").lower()
    primary_loc = ctx.parameter_tags[0].location if ctx.parameter_tags else ParameterLocation.UNKNOWN

    if "json" in ct or primary_loc == ParameterLocation.JSON:
        if enc in ("ascii_plain", "unicode_plain"):
            return 1.0
        if enc == "mixed_unicode_with_percent_encoding":
            return 0.65
        if enc == "ascii_with_percent_encoding":
            return 0.45
        return 0.5

    if primary_loc in (ParameterLocation.QUERY, ParameterLocation.BODY_FORM) or "form" in ct or "urlencoded" in ct:
        if enc == "ascii_with_percent_encoding":
            return 1.0
        if enc == "ascii_plain":
            return 0.75
        if enc == "mixed_unicode_with_percent_encoding":
            return 0.7
        return 0.55

    if enc == "ascii_plain":
        return 0.85
    if enc == "unicode_plain":
        return 0.85
    if enc == "ascii_with_percent_encoding":
        return 0.6
    return 0.5


def _safe_float(row: Mapping[str, str], key: str, default: float = 0.0) -> float:
    raw = row.get(key)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _term_percent_density_fit(
    row: Mapping[str, str], ctx: RequestContext, family_norm: str
) -> float:
    d = _safe_float(row, "percent_encoding_density", 0.0)
    url = (ctx.url or "") + (ctx.path or "")
    wants_pct = "%" in url or "%" in (ctx.path or "") or family_norm == "encoded_attack"

    if wants_pct:
        # Prefer seeds that actually use percent escapes when context/family expects encoding.
        return min(1.0, max(0.0, d * 6.0))

    # Otherwise prefer low density (readable payloads) but do not zero out encoded rows.
    return min(1.0, 1.0 - min(1.0, d * 3.0))


def _term_length_prior(row: Mapping[str, str], target: float = 96.0, span: float = 220.0) -> float:
    n = int(_safe_float(row, "char_len_computed", -1))
    if n < 0:
        n = int(_safe_float(row, "length", 0))
    if n <= 0:
        return 0.2
    dist = abs(float(n) - target)
    return max(0.0, 1.0 - dist / span)


def compute_enriched_seed_score(
    row: Mapping[str, str],
    payload: str,
    context: RequestContext,
    family_normalized: str,
) -> tuple[float, dict[str, float]]:
    """
    Return ``(total_score, breakdown)`` with breakdown including weighted components.

    ``total_score`` is in ``[0, 1]`` (suitable for sorting and logging).
    """
    t_ctx = _term_context_overlap(payload, context)
    t_lab = _term_label_consistency(row)
    t_band = _term_heuristic_band(row)
    t_enc = _term_encoding_alignment(row, context)
    t_pct = _term_percent_density_fit(row, context, family_normalized)
    t_len = _term_length_prior(row)

    breakdown: dict[str, float] = {
        "term_context_overlap": round(t_ctx, 6),
        "term_label_consistency_flag": round(t_lab, 6),
        "term_heuristic_pattern_band": round(t_band, 6),
        "term_encoding_surface_alignment": round(t_enc, 6),
        "term_percent_density_fit": round(t_pct, 6),
        "term_length_prior": round(t_len, 6),
        "weight_context_overlap": W_CONTEXT,
        "weight_label_consistency": W_LABEL,
        "weight_heuristic_band": W_HEURISTIC_BAND,
        "weight_encoding_alignment": W_ENCODING,
        "weight_percent_density": W_PERCENT,
        "weight_length_prior": W_LENGTH,
    }

    total = (
        W_CONTEXT * t_ctx
        + W_LABEL * t_lab
        + W_HEURISTIC_BAND * t_band
        + W_ENCODING * t_enc
        + W_PERCENT * t_pct
        + W_LENGTH * t_len
    )
    breakdown["total_weighted_score"] = round(total, 6)
    return float(total), breakdown
