"""
Post-generation payload validation (lab policy, structural safety).

Validators run **after** composition and **before** ranking or replay. They
enforce **authorized-lab** constraints and keep the experiment record auditable.

**Conservative policy (thesis):** Hard rejection (``severity=ERROR``) is reserved
for conditions that would distort results or violate obvious lab rules (empty
payload, excessive size, disallowed bytes, optional strict URL policy). Ambiguous
or stylistic issues produce **warnings** with stable machine-readable codes so
the thesis can report policy without conflating “blocked” with “flagged for review”.
The generator does not embed these rules; it only invokes :class:`PayloadValidator`,
which keeps **separation of concerns** between synthesis and governance.
"""

from __future__ import annotations

import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

from .context_extractor import RequestContext


class Severity(str, Enum):
    """How serious a validation finding is."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class ValidationFinding:
    """Single human-readable finding from validation."""

    code: str
    message: str
    severity: Severity = Severity.INFO


@dataclass
class ValidationResult:
    """
    Aggregate outcome for one payload candidate.

    Attributes:
        is_valid: True if the candidate may proceed to ranking / execution.
        findings: Ordered list of findings (errors, warnings, hints).
        metrics: Optional numeric tags (e.g. length, charset flags).
    """

    is_valid: bool
    findings: list[ValidationFinding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PayloadCandidate:
    """
    A payload string plus minimal provenance for validation and evaluation.

    Generators attach richer metadata via ``extra`` (retrieval ids, transforms,
    model identifiers). This type is intentionally narrow so validators and
    trial logs depend on a stable interface.
    """

    value: str
    source_label: str
    experiment_group: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class PayloadValidator(ABC):
    """
    Abstract validator: lab policy, structural checks, optional context rules.

    Concrete classes: :class:`LabPayloadValidator` (policy-driven defaults),
    or project-specific subclasses. Hard invalidation should set
    ``is_valid=False`` and ``severity=ERROR`` on at least one finding.
    """

    @abstractmethod
    def validate(
        self,
        candidate: PayloadCandidate,
        context: RequestContext | None = None,
    ) -> ValidationResult:
        """Run checks and return a :class:`ValidationResult`."""

    def validate_batch(
        self,
        candidates: Sequence[PayloadCandidate],
        context: RequestContext | None = None,
    ) -> list[ValidationResult]:
        """Validate multiple candidates; order is preserved."""
        return [self.validate(c, context) for c in candidates]


@dataclass
class LabPayloadValidatorConfig:
    """
    Tunable lab policy (keep identical across A–D unless you study policy change).

    **Reject (ERROR)** defaults: empty payload, oversize, NUL (optional), optional hard
    block on ``http(s)://`` when ``forbid_scheme_urls`` is True.

    **Warn** defaults: control-character ratio, long whitespace runs, HTTP-ish
    fragments in payload-only strings, soft URL hints, context heuristics.
    """

    max_payload_chars: int = 8192
    forbid_null_byte: bool = True
    # When False (default), URL-like data only triggers WRN_* if warn_on_scheme_urls.
    forbid_scheme_urls: bool = False
    warn_on_scheme_urls: bool = True
    warn_on_http_line_fragments: bool = True
    # Ratio of "hard" control chars (excluding tab/LF/CR) to payload length.
    control_char_warn_ratio: float = 0.12
    # If exceeded, treat as ERROR (binary garbage); None disables hard cap.
    control_char_error_ratio: float | None = 0.92
    # Consecutive whitespace codepoints (any kind) triggering a normalization hint.
    duplicate_whitespace_run_threshold: int = 5


# Suspicious patterns for *payload-only* strings that look like raw HTTP (not exhaustive).
_RE_HTTP_VERSION = re.compile(r"\bHTTP/\s*\d\s*\.\s*\d\b", re.IGNORECASE)
_RE_REQUEST_LINE = re.compile(
    r"^\s*(?:GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+/\S+\s+HTTP/\s*\d",
    re.IGNORECASE | re.MULTILINE,
)
_RE_HEADERISH = re.compile(
    r"(?m)^\s*(?:Host|Content-Length|Content-Type|Cookie|Authorization)\s*:",
    re.IGNORECASE,
)


def _control_char_metrics(s: str) -> tuple[int, float]:
    """
    Count Unicode control category Cc plus ASCII C0 controls except TAB/LF/CR.

    Newlines/tabs are common in fuzz strings and are excluded from the "hard" ratio.
    """
    hard = 0
    for ch in s:
        o = ord(ch)
        if ch in "\t\n\r":
            continue
        if o < 32 or o == 127:
            hard += 1
            continue
        if unicodedata.category(ch) == "Cc":
            hard += 1
    n = max(len(s), 1)
    return hard, hard / n


def _max_whitespace_run_length(s: str) -> int:
    if not s:
        return 0
    cur = 0
    best = 0
    for ch in s:
        if ch.isspace():
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


class LabPayloadValidator(PayloadValidator):
    """
    **Authorized-lab-only** concrete validator for the generation pipeline.

    Philosophy: **transparent metrics**, **warnings for ambiguity**, **errors only for
    clear pipeline breakers** (empty, too long, NUL, optional strict URL ban). Generator
    code never embeds these rules — it only calls :meth:`validate`.
    """

    def __init__(self, config: LabPayloadValidatorConfig | None = None) -> None:
        self._cfg = config or LabPayloadValidatorConfig()

    def validate(
        self,
        candidate: PayloadCandidate,
        context: RequestContext | None = None,
    ) -> ValidationResult:
        findings: list[ValidationFinding] = []
        v = candidate.value or ""
        n = len(v)

        ctl_count, ctl_ratio = _control_char_metrics(v)
        ws_run_max = _max_whitespace_run_length(v)
        try:
            byte_len = len(v.encode("utf-8"))
        except UnicodeEncodeError:
            byte_len = -1

        metrics: dict[str, Any] = {
            "payload_char_len": n,
            "payload_byte_len_utf8": byte_len,
            "control_char_count_hard": ctl_count,
            "control_char_ratio_hard": round(ctl_ratio, 6),
            "max_whitespace_run_length": ws_run_max,
            "validator_profile": "lab_payload_v2",
        }

        # Errors below gate the pipeline; warnings below never alone set is_valid False.
        # --- Hard rejects (pipeline / strict policy) ---
        if n == 0:
            findings.append(
                ValidationFinding(
                    code="ERR_EMPTY_PAYLOAD",
                    message="Candidate string is empty.",
                    severity=Severity.ERROR,
                )
            )
        if n > self._cfg.max_payload_chars:
            findings.append(
                ValidationFinding(
                    code="ERR_OVERSIZED",
                    message=(
                        f"Payload length {n} exceeds max_payload_chars="
                        f"{self._cfg.max_payload_chars}."
                    ),
                    severity=Severity.ERROR,
                )
            )
        if self._cfg.forbid_null_byte and "\x00" in v:
            findings.append(
                ValidationFinding(
                    code="ERR_NULL_BYTE",
                    message="Literal NUL byte not allowed under current lab policy.",
                    severity=Severity.ERROR,
                )
            )
        low = v.lower()
        if self._cfg.forbid_scheme_urls and (
            "http://" in low or "https://" in low
        ):
            findings.append(
                ValidationFinding(
                    code="ERR_ABSOLUTE_URL",
                    message=(
                        "Absolute http(s) URL substring blocked (forbid_scheme_urls=True)."
                    ),
                    severity=Severity.ERROR,
                )
            )

        er = self._cfg.control_char_error_ratio
        if er is not None and n > 0 and ctl_ratio >= er:
            findings.append(
                ValidationFinding(
                    code="ERR_EXCESSIVE_CONTROL_CHARS",
                    message=(
                        f"Control-like character ratio {ctl_ratio:.3f} >= {er} "
                        "(likely non-text garbage for this pipeline)."
                    ),
                    severity=Severity.ERROR,
                )
            )

        # --- Warnings (report-friendly, non-blocking) ---
        thr = self._cfg.control_char_warn_ratio
        if n > 0 and ctl_ratio >= thr and not any(
            f.code == "ERR_EXCESSIVE_CONTROL_CHARS" for f in findings
        ):
            findings.append(
                ValidationFinding(
                    code="WRN_HIGH_CONTROL_CHAR_RATIO",
                    message=(
                        f"High density of non-newline control characters "
                        f"(ratio={ctl_ratio:.3f}, threshold={thr})."
                    ),
                    severity=Severity.WARNING,
                )
            )

        wst = self._cfg.duplicate_whitespace_run_threshold
        if ws_run_max >= wst:
            findings.append(
                ValidationFinding(
                    code="WRN_LONG_WHITESPACE_RUN",
                    message=(
                        f"Whitespace run length {ws_run_max} >= {wst}; "
                        "consider normalizing for diff-friendly logs."
                    ),
                    severity=Severity.WARNING,
                )
            )

        if self._cfg.warn_on_scheme_urls and not self._cfg.forbid_scheme_urls:
            if "http://" in low or "https://" in low:
                findings.append(
                    ValidationFinding(
                        code="WRN_URL_SUBSTRING",
                        message=(
                            "Payload contains http:// or https:// (informational for "
                            "XSS/redirect strings; enable forbid_scheme_urls to hard-reject)."
                        ),
                        severity=Severity.WARNING,
                    )
                )

        if self._cfg.warn_on_http_line_fragments and n > 0:
            frag_hits = 0
            if _RE_HTTP_VERSION.search(v):
                frag_hits += 1
            if _RE_REQUEST_LINE.search(v):
                frag_hits += 1
            if _RE_HEADERISH.search(v):
                frag_hits += 1
            metrics["http_fragment_pattern_hits"] = frag_hits
            if frag_hits > 0:
                findings.append(
                    ValidationFinding(
                        code="WRN_HTTP_FRAGMENT_LIKE",
                        message=(
                            "Substring resembles HTTP status line / version / header "
                            f"({frag_hits} pattern class(es)); confirm this is intended "
                            "payload text, not a full request capture."
                        ),
                        severity=Severity.WARNING,
                    )
                )

        # --- Context-aware soft checks (heuristic, never sole hard reject) ---
        if context is not None:
            metrics["context_request_id"] = context.request_id
            ct = (context.content_type or "").lower()
            head = v[: min(400, n)]
            if ct and ("json" in ct) and ("&" in head and "=" in head) and ("{" not in head):
                findings.append(
                    ValidationFinding(
                        code="WRN_CONTEXT_FORM_LIKE_UNDER_JSON_CT",
                        message=(
                            "Content-Type suggests JSON but payload start looks "
                            "form-urlencoded; heuristic only."
                        ),
                        severity=Severity.WARNING,
                    )
                )
            if ct and ("form" in ct or "urlencoded" in ct) and head.lstrip().startswith(
                "{"
            ):
                findings.append(
                    ValidationFinding(
                        code="WRN_CONTEXT_JSON_LIKE_UNDER_FORM_CT",
                        message=(
                            "Content-Type suggests form body but payload starts with "
                            "'{'; heuristic only."
                        ),
                        severity=Severity.WARNING,
                    )
                )

        metrics["finding_error_count"] = sum(1 for f in findings if f.severity == Severity.ERROR)
        metrics["finding_warning_count"] = sum(
            1 for f in findings if f.severity == Severity.WARNING
        )
        metrics["finding_info_count"] = sum(1 for f in findings if f.severity == Severity.INFO)

        has_error = any(f.severity == Severity.ERROR for f in findings)
        return ValidationResult(is_valid=not has_error, findings=findings, metrics=metrics)


def example_validate_demo() -> None:
    """Tiny sanity demo for reports / notebooks (no pytest dependency)."""
    from .context_extractor import ParameterLocation, ParameterMeta, RequestContext

    val = LabPayloadValidator()
    ok = val.validate(PayloadCandidate("<script>alert(1)</script>", "demo"), None)
    assert ok.is_valid
    bad = val.validate(PayloadCandidate("", "demo"), None)
    assert not bad.is_valid and any(f.code == "ERR_EMPTY_PAYLOAD" for f in bad.findings)

    ctx = RequestContext(
        request_id="1",
        method="POST",
        url="http://lab/x",
        path="/x",
        content_type="application/json",
        parameter_tags=(ParameterMeta("q", ParameterLocation.JSON),),
    )
    mixed = val.validate(PayloadCandidate("a=1&b=2", "demo"), ctx)
    assert any(f.code == "WRN_CONTEXT_FORM_LIKE_UNDER_JSON_CT" for f in mixed.findings)


if __name__ == "__main__":
    example_validate_demo()
    print("payload_validator example_validate_demo: ok")


# -----------------------------------------------------------------------------
# Related components (separate modules): generator, ranker, adaptive controller,
# evaluation pipeline. Keep validator rules stationary across A–D for fair runs.
# -----------------------------------------------------------------------------
