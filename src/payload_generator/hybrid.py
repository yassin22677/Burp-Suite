"""Deterministic hybrid transform chains (:class:`HybridCandidateGenerator`)."""

from __future__ import annotations

import random
import re
from typing import Sequence

from ..context_extractor import ParameterLocation
from .schemas import ExplanationStep, GenerationRequest, GenerativeCandidate, RetrievedSeed
from ._utils import _normalize_family, _rng_for_request

# ---------------------------------------------------------------------------
# Hybrid candidate generation (retrieval + deterministic transforms)
# ---------------------------------------------------------------------------

# Ordered transform chains per family: each chain is a list of step ids executed after
# ``strip_http_tail``. Steps are deterministic; ``random_seed`` only shuffles which
# chains are tried first when trimming to ``n_candidates``.
#
# Coverage rationale (thesis / ablation): static baselines use raw KB strings; hybrid
# arms must expose *distinct named compositions* (comment styles, encodings, delimiters,
# markup shapes) without open-ended byte mutation. Extra chains below add (1) SQL
# comment stacking and balance+line-comment variants absent from the original set,
# (2) XSS img/onerror vs svg/script/event patterns, plus script-then-angle-encoding,
# (3) nested percent layers for encoded_attack WAF bypass narratives, (4) shell
# ``&`` separation vs ``|``/``;``/backticks, (5) richer ``other`` catch-all encoding
# paths so the hybrid arm is not nearly identical to retrieval-only for misc rows.
_CHAIN_TEMPLATES: dict[str, list[list[str]]] = {
    "sql": [
        ["slot_context", "sql_double_quote_once", "sql_suffix_comment_dashes"],
        ["slot_context", "sql_balance_odd_quotes", "sql_suffix_comment_hash"],
        ["slot_context", "sql_balance_odd_quotes", "sql_suffix_comment_dashes"],
        ["slot_context", "sql_prefix_comment_c_style"],
        ["slot_context", "sql_prefix_comment_c_style", "sql_suffix_comment_dashes"],
        ["slot_context", "enc_percent_prefix", "sql_suffix_comment_dashes"],
    ],
    "xss": [
        ["slot_context", "xss_wrap_script_lowercase"],
        ["slot_context", "xss_wrap_script_lowercase", "xss_percent_encode_angles"],
        ["slot_context", "xss_svg_onload_wrapper"],
        ["slot_context", "xss_img_onerror_wrapper"],
        ["slot_context", "xss_percent_encode_angles"],
        ["slot_context", "xss_event_handler_attr_shape"],
    ],
    "encoded_attack": [
        ["slot_context", "enc_percent_prefix"],
        ["slot_context", "enc_double_percent_prefix"],
        ["slot_context", "enc_percent_full_string"],
        ["slot_context", "enc_percent_prefix", "enc_double_percent_prefix"],
    ],
    "cmd": [
        ["slot_context", "cmd_pipe_prefix"],
        ["slot_context", "cmd_backtick_wrap"],
        ["slot_context", "cmd_semicolon_prefix"],
        ["slot_context", "cmd_ampersand_prefix"],
    ],
    "other": [
        ["slot_context", "generic_trim_duplicate_separators"],
        ["slot_context", "generic_trim_duplicate_separators", "enc_percent_prefix"],
        ["slot_context", "enc_percent_prefix"],
        ["slot_context", "enc_percent_full_string"],
    ],
}


class HybridCandidateGenerator:
    """
    Retrieval-augmented **structured** generator: executes **named transform chains**
    on real seeds. Each primitive appends an :class:`ExplanationStep` (thesis trace).

    The transform vocabulary is **finite and named** (not open-ended string mutation),
    which supports explainability and controlled lab use. Randomness
    (**``random_seed``**) affects only **chain ordering** among seeds and within
    equal-score retrieval bands—not emission of arbitrary bytes.
    """

    _HTTP_TAIL = re.compile(r"\sHTTP/\d+\.\d+\s*$", re.IGNORECASE)

    def generate(
        self,
        request: GenerationRequest,
        seeds: Sequence[RetrievedSeed],
    ) -> list[GenerativeCandidate]:
        """Produce up to ``request.n_candidates`` candidates (may be fewer if seeds empty)."""
        if not seeds:
            return []

        rng = _rng_for_request(request)
        max_len = int(request.options.get("max_payload_len", 2048))
        fam = _normalize_family(request.family)
        templates = list(_CHAIN_TEMPLATES.get(fam, _CHAIN_TEMPLATES["other"]))
        if request.options.get("deterministic_transform_order"):
            templates.sort(key=lambda chain: "+".join(chain))
        else:
            rng.shuffle(templates)

        out: list[GenerativeCandidate] = []
        si = 0
        while len(out) < request.n_candidates and si < len(seeds):
            seed = seeds[si]
            si += 1
            base = self._strip_http_tail(seed.payload)
            expl_base: list[ExplanationStep] = [
                ExplanationStep(
                    "retrieve_seed",
                    "Conditioning seed selected (retrieval score + breakdown in metadata).",
                    {
                        "seed_id": seed.seed_id,
                        "retrieval_score": seed.score,
                        "retrieval_total_weighted": seed.score_breakdown.get(
                            "total_weighted_score", seed.score
                        ),
                    },
                ),
                ExplanationStep(
                    "strip_http_tail",
                    "Removed trailing HTTP version token when present (capture artifact).",
                    {},
                ),
            ]
            for chain in templates:
                if len(out) >= request.n_candidates:
                    break
                val, t_ids, expl = self._run_chain(base, chain, request, seed, expl_base)
                # Arm C thesis rule: do not emit raw KB strings (arm B). Skip chains that leave the
                # payload identical to the stripped seed so transforms must differentiate C from B.
                _arm = request.options.get("thesis_arm")
                if _arm in ("C", "D") and val.strip() == base.strip():
                    continue
                out.append(
                    self._wrap_candidate(
                        value=val[:max_len],
                        request=request,
                        seed=seed,
                        transforms=t_ids,
                        explanation=expl,
                        chain_id="+".join(chain),
                    )
                )

        return out[: request.n_candidates]

    def _run_chain(
        self,
        base: str,
        chain: list[str],
        request: GenerationRequest,
        seed: RetrievedSeed,
        expl_base: list[ExplanationStep],
    ) -> tuple[str, list[str], list[ExplanationStep]]:
        val = base
        t_ids = ["strip_http_tail"]
        expl: list[ExplanationStep] = list(expl_base)
        for step_id in chain:
            fn: Callable[..., tuple[str, str, ExplanationStep]] = getattr(self, f"_step_{step_id}")
            val, tid, step = fn(val, request, seed)
            t_ids.append(tid)
            expl.append(step)
        return val, t_ids, expl

    def _wrap_candidate(
        self,
        value: str,
        request: GenerationRequest,
        seed: RetrievedSeed,
        transforms: list[str],
        explanation: list[ExplanationStep],
        chain_id: str = "",
    ) -> GenerativeCandidate:
        ctx = request.context
        primary_loc = (
            ctx.parameter_tags[0].location.value if ctx.parameter_tags else "none"
        )
        return GenerativeCandidate(
            value=value,
            family=_normalize_family(request.family),
            retrieval_ids=[seed.seed_id],
            transforms=transforms,
            explanation=explanation,
            metadata={
                "lab_run_id": request.lab_run_id,
                "generation_engine": "hybrid_chain_v2",
                "transform_chain_id": chain_id,
                "transform_depth": len(transforms),
                "retrieval_score": seed.score,
                "retrieval_score_breakdown": dict(seed.score_breakdown),
                "content_type_context": ctx.content_type,
                "primary_parameter_location": primary_loc,
                "random_seed_used": request.options.get("random_seed"),
                "generator_mode": request.options.get("generator_mode"),
            },
        )

    @classmethod
    def _strip_http_tail(cls, s: str) -> str:
        return cls._HTTP_TAIL.sub("", s).rstrip()

    # --- Transform steps (each: value -> (new_value, transform_id, ExplanationStep)) ---

    def _step_slot_context(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = seed
        ctx = request.context
        ct = (ctx.content_type or "").lower()
        if not ctx.parameter_tags:
            return (
                val,
                "slot_skipped",
                ExplanationStep(
                    "slot_context",
                    "No parameter_tags; payload left unchanged (inject point unknown).",
                    {"content_type": ctx.content_type},
                ),
            )
        pm = ctx.parameter_tags[0]
        name = pm.name
        loc = pm.location
        detail: dict[str, Any] = {
            "parameter": name,
            "location": loc.value,
            "content_type": ctx.content_type,
        }
        # JSON-shaped transport: escape as a JSON string literal.
        if loc == ParameterLocation.JSON or (
            "json" in ct and "form" not in ct and loc != ParameterLocation.BODY_FORM
        ):
            esc = val.replace("\\", "\\\\").replace('"', '\\"')
            out = f'"{esc}"'
            return (
                out,
                "slot_json_string",
                ExplanationStep(
                    "slot_context",
                    "JSON insertion context: wrapped as escaped string literal.",
                    detail,
                ),
            )
        if loc in (ParameterLocation.HEADER,):
            out = f"{name}: {val}"
            return (
                out,
                "slot_header_shape",
                ExplanationStep(
                    "slot_context",
                    "Header-shaped composition (lab template; not a full HTTP message).",
                    detail,
                ),
            )
        if loc == ParameterLocation.COOKIE:
            out = f"{name}={val}"
            return (
                out,
                "slot_cookie",
                ExplanationStep(
                    "slot_context",
                    "Cookie-style name=value composition.",
                    detail,
                ),
            )
        prefix = f"{name}="
        if val.lower().startswith(prefix.lower()):
            return (
                val,
                "slot_identity",
                ExplanationStep(
                    "slot_context",
                    "Payload already prefixed with parameter assignment.",
                    detail,
                ),
            )
        return (
            prefix + val,
            "slot_query_or_form",
            ExplanationStep(
                "slot_context",
                "Query/form-style name= prefix from primary parameter tag.",
                detail,
            ),
        )

    def _step_sql_double_quote_once(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        if "'" in val and "''" not in val:
            out = val.replace("'", "''", 1)
            return (
                out,
                "sql_double_quote_once",
                ExplanationStep(
                    "sql_escape",
                    "SQL: doubled first single-quote (classic escaping variant).",
                    {"occurrence": 1},
                ),
            )
        return (
            val,
            "sql_double_quote_skip",
            ExplanationStep(
                "sql_escape",
                "SQL: skip doubling (no lone single-quote candidate).",
                {},
            ),
        )

    def _step_sql_balance_odd_quotes(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        n = val.count("'")
        if n % 2 == 1:
            out = val + "'"
            return (
                out,
                "sql_balance_quote",
                ExplanationStep(
                    "sql_quote_balance",
                    "SQL: appended closing single-quote (odd count before step).",
                    {"quotes_before": n},
                ),
            )
        return (
            val,
            "sql_balance_skip",
            ExplanationStep(
                "sql_quote_balance",
                "SQL: quote count already even; no closure appended.",
                {"quotes_before": n},
            ),
        )

    def _step_sql_suffix_comment_dashes(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        s = val.rstrip()
        if s.endswith("--") or s.endswith("*/"):
            return (
                val,
                "sql_comment_skip",
                ExplanationStep(
                    "sql_comment",
                    "SQL: suffix comment skipped (already present).",
                    {},
                ),
            )
        out = s + " -- "
        return (
            out,
            "sql_comment_dashes",
            ExplanationStep(
                "sql_comment",
                "SQL: appended line comment opener (--) for dialects that accept it.",
                {},
            ),
        )

    def _step_sql_suffix_comment_hash(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        s = val.rstrip()
        if "#" in s[-8:]:
            return (
                val,
                "sql_hash_skip",
                ExplanationStep("sql_comment", "SQL: hash comment already near suffix.", {}),
            )
        return (
            s + " #",
            "sql_comment_hash",
            ExplanationStep(
                "sql_comment",
                "SQL: appended hash-style comment starter (MySQL-family heuristic).",
                {},
            ),
        )

    def _step_sql_prefix_comment_c_style(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        if val.lstrip().startswith("/*"):
            return (
                val,
                "sql_c_comment_skip",
                ExplanationStep("sql_comment", "SQL: already starts with block comment.", {}),
            )
        return (
            "/*" + val,
            "sql_comment_c_prefix",
            ExplanationStep(
                "sql_comment",
                "SQL: prefixed C-style block comment opener (stacked-query lab pattern).",
                {},
            ),
        )

    def _step_enc_percent_prefix(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        n = min(36, len(val))
        frag = val[:n]
        enc = "".join(f"%{ord(c):02x}" for c in frag)
        out = enc + val[n:]
        return (
            out,
            "enc_percent_prefix",
            ExplanationStep(
                "encoding",
                "Percent-encoded first N characters (deterministic N=min(36,len)).",
                {"n_encoded": n},
            ),
        )

    def _step_enc_double_percent_prefix(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        n = min(8, len(val))
        frag = val[:n]
        enc = "".join(f"%25{ord(c):02x}" for c in frag)
        out = enc + val[n:]
        return (
            out,
            "enc_double_percent_prefix",
            ExplanationStep(
                "encoding",
                "Double-percent encoding on first N chars (nested decoding labs).",
                {"n_encoded": n},
            ),
        )

    def _step_enc_percent_full_string(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        out = "".join(f"%{ord(c):02x}" for c in val)
        return (
            out,
            "enc_percent_full",
            ExplanationStep(
                "encoding",
                "Full-string percent encoding (byte-preserving, explainable).",
                {"original_len": len(val)},
            ),
        )

    def _step_xss_wrap_script_lowercase(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        low = val.lower()
        if "<script" in low:
            return (
                val,
                "xss_script_skip",
                ExplanationStep("xss_wrap", "XSS: script tag already present.", {}),
            )
        out = f"<script>{val}</script>"
        return (
            out,
            "xss_script_wrap",
            ExplanationStep(
                "xss_wrap",
                "XSS: wrapped payload in lowercase script element (markup context).",
                {},
            ),
        )

    def _step_xss_svg_onload_wrapper(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        out = '"><svg/onload=alert(1)><!--' + val + "--></svg>"
        return (
            out,
            "xss_svg_onload",
            ExplanationStep(
                "xss_wrap",
                "XSS: break-out + svg/onload scaffold with seed in HTML comment.",
                {"pattern": "svg_onload_comment_embed"},
            ),
        )

    def _step_xss_img_onerror_wrapper(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        low = val.lower()
        if "<img" in low and "onerror" in low:
            return (
                val,
                "xss_img_onerror_skip",
                ExplanationStep(
                    "xss_wrap",
                    "XSS: img/onerror scaffold already present; left unchanged.",
                    {},
                ),
            )
        out = '\'"><img src=x onerror=alert(1)><!--' + val + "-->"
        return (
            out,
            "xss_img_onerror",
            ExplanationStep(
                "xss_wrap",
                "XSS: break-out + img/onerror scaffold with seed in HTML comment "
                "(distinct from svg/script/event-attr chains).",
                {"pattern": "img_onerror_comment_embed"},
            ),
        )

    def _step_xss_percent_encode_angles(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        out = val.replace("<", "%3c").replace(">", "%3e")
        return (
            out,
            "xss_pct_angles",
            ExplanationStep(
                "xss_encoding",
                "XSS: percent-encoded angle brackets where present.",
                {},
            ),
        )

    def _step_xss_event_handler_attr_shape(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        out = '" onmouseover="' + val + '" x="'
        return (
            out,
            "xss_event_attr",
            ExplanationStep(
                "xss_attr_breakout",
                "XSS: attribute-breakout shaped prefix/suffix (quoted context heuristic).",
                {},
            ),
        )

    def _step_cmd_pipe_prefix(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        s = val.lstrip()
        if s.startswith("|") or s.startswith(";"):
            return (
                val,
                "cmd_pipe_skip",
                ExplanationStep("cmd", "Command chaining token already leading.", {}),
            )
        return (
            "|" + val,
            "cmd_pipe_prefix",
            ExplanationStep(
                "cmd",
                "Prepended pipe for shell concatenation contexts (lab-only).",
                {},
            ),
        )

    def _step_cmd_backtick_wrap(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        if "`" in val:
            return (
                val,
                "cmd_backtick_skip",
                ExplanationStep("cmd", "Backtick already in payload; no wrap.", {}),
            )
        return (
            "`" + val + "`",
            "cmd_backtick_wrap",
            ExplanationStep(
                "cmd",
                "Wrapped payload in backticks (command-substitution shaped).",
                {},
            ),
        )

    def _step_cmd_semicolon_prefix(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        s = val.lstrip()
        if s.startswith(";"):
            return (
                val,
                "cmd_semi_skip",
                ExplanationStep("cmd", "Semicolon already leading.", {}),
            )
        return (
            ";" + val,
            "cmd_semicolon_prefix",
            ExplanationStep(
                "cmd",
                "Prepended command separator (stacked-command lab pattern).",
                {},
            ),
        )

    def _step_cmd_ampersand_prefix(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        s = val.lstrip()
        if s.startswith(("&", "|", ";")):
            return (
                val,
                "cmd_ampersand_skip",
                ExplanationStep(
                    "cmd",
                    "Ampersand prefix skipped (another chaining token already leads).",
                    {},
                ),
            )
        return (
            "&" + val,
            "cmd_ampersand_prefix",
            ExplanationStep(
                "cmd",
                "Prepended ampersand for background/stacked-command contexts (lab heuristic).",
                {},
            ),
        )

    def _step_generic_trim_duplicate_separators(
        self, val: str, request: GenerationRequest, seed: RetrievedSeed
    ) -> tuple[str, str, ExplanationStep]:
        _ = request, seed
        out = re.sub(r"\|\|+", "|", val)
        changed = out != val
        return (
            out,
            "generic_trim_pipes" if changed else "generic_trim_noop",
            ExplanationStep(
                "generic",
                "Collapsed duplicate pipe separators for cleaner diffing."
                if changed
                else "No duplicate pipe runs to trim.",
                {"changed": changed},
            ),
        )


