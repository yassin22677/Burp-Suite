"""
Execution backends: turn (request context + payload candidates) into :class:`TrialRecord`.

This layer sits **below** aggregation (:mod:`evaluation_pipeline`) and **beside** the
generative pipeline (:mod:`payload_generator`). It does **not** perform autonomous
targeting, Burp automation, or exploitation. This repository ships **offline replay**
(:class:`OfflineReplayExecutionBackend`) for fixture rows or outcomes you observed
elsewhere (e.g. manual Intruder).

**Experiment arms A–D**

- **A–D** share the same :class:`TrialRecord` shape. The :class:`ExperimentGroup` on
  each record identifies the arm; the backend does not change group semantics.
- **Offline replay** (:class:`OfflineReplayExecutionBackend`) is appropriate when you
  already have responses from Burp Intruder, a lab proxy, or a spreadsheet—aligned
  1:1 with each :class:`~payload_validator.PayloadCandidate`. This preserves
  reproducibility and keeps HTTP execution **outside** this repository if desired.
- Any **live** HTTP client would be a separate, explicitly scoped component; it is
  **not** part of the supported manual Burp workflow in this repository.

Example (offline fixtures)::

    from src.context_extractor import RequestContextExtractor
    from src.evaluation import ExperimentGroup
    from src.execution_backend import (
        ExecutionBatch,
        OfflineReplayExecutionBackend,
        replay_outcomes_from_mapping_rows,
    )
    from src.payload_validator import PayloadCandidate

    ctx = RequestContextExtractor().extract({"url": "https://lab.example/x", "method": "GET"})
    cands = [
        PayloadCandidate(value="' OR 1=1--", source_label="static"),
        PayloadCandidate(value="<script>x</script>", source_label="static"),
    ]
    outcomes = [
        {"trial_status_code": 200, "trial_response_length": 100},
        {"trial_status_code": 500, "trial_response_length": 220, "is_abnormal": True},
    ]
    backend = OfflineReplayExecutionBackend()
    batch = ExecutionBatch(
        request_context=ctx,
        candidates=cands,
        group=ExperimentGroup.STATIC_DATASET,
        baseline_status_code=200,
        baseline_response_length=100,
        replay_outcomes=outcomes,
    )
    trials = backend.execute_batch(batch)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .context_extractor import RequestContext
from .evaluation import ExperimentGroup, TrialRecord
from .payload_validator import PayloadCandidate


@dataclass
class ExecutionBatch:
    """
    One execution unit: a single :class:`RequestContext`, a list of candidates for one arm,
    optional baseline metadata, and (for offline replay) parallel outcome rows.

    ``replay_outcomes[i]`` corresponds to ``candidates[i]``. Populate ``replay_outcomes``
    when using :class:`OfflineReplayExecutionBackend`; omit or set to ``None`` for
    backends that compute responses themselves.
    """

    request_context: RequestContext
    candidates: list[PayloadCandidate]
    group: ExperimentGroup
    baseline_status_code: int | None = None
    baseline_response_length: int | None = None
    replay_outcomes: list[dict[str, Any]] | None = None
    trial_id_prefix: str = "trial"

    def __post_init__(self) -> None:
        if not self.candidates:
            raise ValueError("ExecutionBatch.candidates must be non-empty.")


class ExecutionBackend(ABC):
    """
    Abstract execution surface for lab trials.

    Implementations must not implement unauthorized scanning or multi-target
    orchestration; they only materialize :class:`TrialRecord` rows from permitted
    lab workflows.
    """

    @abstractmethod
    def execute_batch(self, batch: ExecutionBatch) -> list[TrialRecord]:
        """
        Run (or replay) one batch and return one :class:`TrialRecord` per candidate.

        The batch's :attr:`ExecutionBatch.group` is the experiment arm for every
        returned record.
        """
        raise NotImplementedError


def replay_outcomes_from_mapping_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """
    Normalize outcome dicts from Burp exports or JSON fixtures into the keys used
    by :class:`OfflineReplayExecutionBackend`.

    Accepts aliases: ``status`` / ``trial_status_code``, ``length`` /
    ``trial_response_length``. Unknown keys are preserved in the returned dicts
    for optional propagation into ``TrialRecord.tags``.
    """
    normalized: list[dict[str, Any]] = []
    for raw in rows:
        d = dict(raw)
        if "trial_status_code" not in d and "status" in d:
            d["trial_status_code"] = d.get("status")
        if "trial_response_length" not in d and "length" in d:
            d["trial_response_length"] = d.get("length")
        normalized.append(d)
    return normalized


class OfflineReplayExecutionBackend(ExecutionBackend):
    """
    Materialize :class:`TrialRecord` rows from **pre-recorded** trial outcomes.

    Use this when responses were already observed (Burp Intruder table, lab proxy
    logs, or normalized CSV rows exported to JSON). No sockets are opened.

    Each outcome row should include at least ``trial_status_code`` and
    ``trial_response_length`` (ints or numeric strings). Optional booleans
    ``is_abnormal`` and ``is_invalid_candidate`` are copied into ``TrialRecord.tags``
    for :mod:`evaluation_pipeline` compatibility.
    """

    def execute_batch(self, batch: ExecutionBatch) -> list[TrialRecord]:
        if batch.replay_outcomes is None:
            raise ValueError(
                "OfflineReplayExecutionBackend requires ExecutionBatch.replay_outcomes "
                "with one dict per candidate (use replay_outcomes_from_mapping_rows if needed)."
            )
        if len(batch.replay_outcomes) != len(batch.candidates):
            raise ValueError(
                f"replay_outcomes length ({len(batch.replay_outcomes)}) must match "
                f"candidates length ({len(batch.candidates)})."
            )

        records: list[TrialRecord] = []
        for i, (cand, out) in enumerate(zip(batch.candidates, batch.replay_outcomes, strict=True)):
            tags: dict[str, Any] = {}
            if "is_abnormal" in out:
                tags["is_abnormal"] = bool(out["is_abnormal"])
            if "is_invalid_candidate" in out:
                tags["is_invalid_candidate"] = bool(out["is_invalid_candidate"])
            # carry over any extra annotation keys (excluding core fields we map explicitly)
            reserved = {
                "trial_status_code",
                "trial_response_length",
                "status",
                "length",
                "is_abnormal",
                "is_invalid_candidate",
            }
            for k, v in out.items():
                if k not in reserved:
                    tags[k] = v

            def _to_int_opt(val: Any) -> int | None:
                if val is None or (isinstance(val, str) and not str(val).strip()):
                    return None
                try:
                    return int(float(val))
                except (TypeError, ValueError):
                    return None

            trial_status = _to_int_opt(out.get("trial_status_code"))
            trial_len = _to_int_opt(out.get("trial_response_length"))

            records.append(
                TrialRecord(
                    trial_id=f"{batch.trial_id_prefix}_{i}",
                    group=batch.group,
                    request_context=batch.request_context,
                    candidate=cand,
                    baseline_status_code=batch.baseline_status_code,
                    baseline_response_length=batch.baseline_response_length,
                    trial_status_code=trial_status,
                    trial_response_length=trial_len,
                    tags=tags,
                )
            )
        return records


def resolve_execution_batch(
    batches: Mapping[Any, ExecutionBatch],
    group: ExperimentGroup,
) -> ExecutionBatch:
    """
    Look up an :class:`ExecutionBatch` for ``group`` using enum or string value keys.
    """
    if group in batches:
        return batches[group]
    key = group.value
    if key in batches:
        return batches[key]
    raise KeyError(
        f"No ExecutionBatch for group {group!r}. Keys present: {list(batches.keys())!r}"
    )
