"""Experiment arms (A–D), trial records, and :class:`EvaluationPipeline` over :mod:`execution_backend`.

Manual metrics and CSVs: use :mod:`evaluation_pipeline` and the ``scripts/`` CLIs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence, cast

from .context_extractor import RequestContext
from .payload_validator import PayloadCandidate


class ExperimentGroup(str, Enum):
    """
    Experiment arm label; keep stable for logs and thesis figures.

    A: Baseline Burp inputs (fixed built-in / default configuration).
    B: Static payloads sampled from the cleaned dataset (no generation).
    C: Context-aware generated payloads (no adaptive controller).
    D: Generated payloads with adaptive selection (e.g. contextual bandit).
    """

    BASELINE_BURP = "A_baseline_burp"
    STATIC_DATASET = "B_static_dataset"
    GENERATED = "C_generated"
    GENERATED_ADAPTIVE = "D_generated_adaptive"


@dataclass
class TrialRecord:
    """
    One fuzz attempt on a single request context under one experiment group.

    Fields are intentionally generic so HTTP outcomes can be filled from **your**
    observations (e.g. rows you exported from Intruder) or from **offline** replay
    fixtures—without coupling to Burp APIs or types here.
    """

    trial_id: str
    group: ExperimentGroup
    request_context: RequestContext
    candidate: PayloadCandidate
    baseline_status_code: int | None = None
    baseline_response_length: int | None = None
    trial_status_code: int | None = None
    trial_response_length: int | None = None
    tags: dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricSummary:
    """
    Aggregated metrics for one arm (or a slice). Numeric values are in
    ``aggregates`` (keys align with
    :func:`evaluation_pipeline.comparison_metrics_table`).
    """

    group: ExperimentGroup | None = None
    trial_count: int = 0
    aggregates: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class EvaluationPipeline:
    """
    Thin orchestration over :mod:`evaluation_pipeline`.

    For the usual **manual** lab path, you will consume CSVs from
    ``normalize_burp_results.py`` directly via :mod:`evaluation_pipeline` helpers;
    this class is mainly for programmatic / thesis batch setups with an
    :class:`execution_backend.ExecutionBackend`.

    CSV export remains :func:`evaluation_pipeline.save_comparison_metrics` — not
    reimplemented here.
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self.config = dict(config or {})

    def run_group(self, group: ExperimentGroup) -> list[TrialRecord]:
        """
        Run all trials for one experiment arm using ``config['execution_backend']``.

        Requires:

        - ``config['execution_backend']``: an :class:`execution_backend.ExecutionBackend`
          instance (e.g. :class:`execution_backend.OfflineReplayExecutionBackend`).
        - ``config['execution_batches']``: mapping from :class:`ExperimentGroup` **or**
          group value string → :class:`execution_backend.ExecutionBatch` for that arm.

        The batch for ``group`` must have ``batch.group == group``. Returns fresh
        :class:`TrialRecord` rows suitable for :meth:`summarize` or appending to
        ``config['trials']``.

        If no backend is configured, raises :class:`NotImplementedError` (legacy
        behavior): supply ``config['trials']`` and use :meth:`run_all` instead.

        Raises:
            NotImplementedError: If ``execution_backend`` is missing.
            TypeError: If ``execution_backend`` is not an ``ExecutionBackend``.
            ValueError: If ``execution_batches`` is missing or invalid.
            KeyError: If no batch is registered for ``group``.
        """
        from .execution_backend import ExecutionBackend, resolve_execution_batch

        backend_any = self.config.get("execution_backend")
        if backend_any is None:
            raise NotImplementedError(
                "run_group requires config['execution_backend'] (see execution_backend module) "
                "or collect TrialRecord rows in config['trials'] and use run_all / summarize."
            )
        if not isinstance(backend_any, ExecutionBackend):
            raise TypeError(
                f"config['execution_backend'] must be an ExecutionBackend, got {type(backend_any)!r}."
            )
        backend = cast(ExecutionBackend, backend_any)

        batches_any = self.config.get("execution_batches")
        if not isinstance(batches_any, Mapping):
            raise ValueError(
                "config['execution_batches'] must be a mapping (ExperimentGroup or str value → ExecutionBatch) "
                "when execution_backend is set."
            )

        batch = resolve_execution_batch(batches_any, group)
        if batch.group != group:
            raise ValueError(
                f"ExecutionBatch.group is {batch.group!r} but run_group was called with {group!r}."
            )
        return backend.execute_batch(batch)

    def run_groups_in_order(
        self,
        groups: Sequence[ExperimentGroup] | None = None,
        *,
        append_to_config_trials: bool = True,
        skip_missing_batches: bool = True,
    ) -> list[TrialRecord]:
        """
        Execute every configured arm in ``groups`` order (default **A → B → C → D**).

        For each group, looks up ``config['execution_batches']``; if
        ``skip_missing_batches`` is True, groups with no batch are skipped; if False,
        a missing batch raises :class:`KeyError`.

        When ``append_to_config_trials`` is True, returned rows are also appended to
        ``config['trials']`` (list is created if absent) for :meth:`run_all` / thesis
        tables.

        Requires the same ``execution_backend`` and ``execution_batches`` setup as
        :meth:`run_group`.
        """
        order: tuple[ExperimentGroup, ...] = (
            tuple(groups)
            if groups is not None
            else (
                ExperimentGroup.BASELINE_BURP,
                ExperimentGroup.STATIC_DATASET,
                ExperimentGroup.GENERATED,
                ExperimentGroup.GENERATED_ADAPTIVE,
            )
        )
        batches_any = self.config.get("execution_batches")
        if not isinstance(batches_any, Mapping):
            raise ValueError(
                "run_groups_in_order requires config['execution_batches'] to be a mapping."
            )

        def _has_batch(g: ExperimentGroup) -> bool:
            return g in batches_any or g.value in batches_any

        accumulated: list[TrialRecord] = []
        for g in order:
            if skip_missing_batches and not _has_batch(g):
                continue
            accumulated.extend(self.run_group(g))
        if append_to_config_trials:
            bucket = self.config.setdefault("trials", [])
            if not isinstance(bucket, list):
                raise TypeError("config['trials'] must be a list when append_to_config_trials is True.")
            bucket.extend(accumulated)
        return accumulated

    def summarize(self, trials: list[TrialRecord]) -> list[MetricSummary]:
        """
        One :class:`MetricSummary` per arm present in ``trials``.

        Uses :func:`evaluation_pipeline.comparison_metrics_table` only.
        """
        from .evaluation_pipeline import comparison_metrics_table

        if not trials:
            return []
        table = comparison_metrics_table(trials)
        return _metric_summaries_from_comparison_table(table)

    def run_all(
        self, *, include_empty_groups: bool = False
    ) -> dict[ExperimentGroup, MetricSummary]:
        """
        Partition ``config['trials']`` by :attr:`TrialRecord.group` and summarize each arm.

        **Requires** ``config['trials']``: ``list[TrialRecord]``. Does not call Burp.

        Args:
            include_empty_groups: If True, include every :class:`ExperimentGroup` with
                zero trials (empty aggregates) for complete thesis tables.

        Raises:
            ValueError: If ``trials`` is missing or not a list.
            TypeError: If any list element is not a :class:`TrialRecord`.
            RuntimeError: If partitioning is inconsistent (multiple summary rows per arm).
        """
        trials_any = self.config.get("trials")
        if not isinstance(trials_any, list):
            raise ValueError(
                "run_all requires config['trials'] as list[TrialRecord]. "
                "No HTTP execution is performed in this method."
            )
        by_arm: dict[ExperimentGroup, list[TrialRecord]] = {}
        for tr in trials_any:
            if not isinstance(tr, TrialRecord):
                raise TypeError(
                    f"config['trials'] must hold TrialRecord instances, got {type(tr)!r}."
                )
            by_arm.setdefault(tr.group, []).append(tr)

        result: dict[ExperimentGroup, MetricSummary] = {}
        arms = (
            list(ExperimentGroup)
            if include_empty_groups
            else sorted(by_arm.keys(), key=lambda g: g.value)
        )
        for g in arms:
            subset = by_arm.get(g, [])
            if not subset:
                if include_empty_groups:
                    result[g] = MetricSummary(
                        group=g,
                        trial_count=0,
                        aggregates={},
                        notes=["No trials for this arm (include_empty_groups=True)."],
                    )
                continue
            rows = self.summarize(subset)
            if len(rows) != 1:
                raise RuntimeError(
                    f"Expected one MetricSummary for arm {g!s}, got {len(rows)} — "
                    "trials in a partition should share the same group."
                )
            result[g] = rows[0]
        return result

    @staticmethod
    def metric_summary_to_thesis_dict(summary: MetricSummary) -> dict[str, Any]:
        """
        Flat row for tables / ``DataFrame``: ``metric_*`` keys plus group labels.
        """
        out: dict[str, Any] = {
            "experiment_group": summary.group.value if summary.group else None,
            "experiment_group_name": summary.group.name if summary.group else None,
            "trial_count": summary.trial_count,
            "notes": "; ".join(summary.notes) if summary.notes else "",
        }
        for k, v in summary.aggregates.items():
            out[f"metric_{k}"] = v
        return out

    @staticmethod
    def summaries_to_thesis_rows(summaries: list[MetricSummary]) -> list[dict[str, Any]]:
        return [EvaluationPipeline.metric_summary_to_thesis_dict(s) for s in summaries]

    @staticmethod
    def metric_summary_to_jsonable(summary: MetricSummary) -> dict[str, Any]:
        """Nested JSON-friendly dict (preserves ``aggregates`` and ``notes`` list)."""
        return {
            "group": summary.group.value if summary.group else None,
            "group_name": summary.group.name if summary.group else None,
            "trial_count": summary.trial_count,
            "aggregates": dict(summary.aggregates),
            "notes": list(summary.notes),
        }


def _metric_summaries_from_comparison_table(table: Any) -> list[MetricSummary]:
    """Convert comparison-metrics DataFrame rows to :class:`MetricSummary` (glue only)."""
    import pandas as pd

    from .evaluation_pipeline import COL_GROUP

    if table is None or getattr(table, "empty", True):
        return []
    metric_cols = [c for c in table.columns if c not in (COL_GROUP, "trial_count")]
    out: list[MetricSummary] = []
    for _, row in table.iterrows():
        gval = str(row[COL_GROUP])
        group_enum = next((g for g in ExperimentGroup if g.value == gval), None)
        if group_enum is None:
            continue
        agg: dict[str, float] = {}
        for c in metric_cols:
            val = row[c]
            if pd.isna(val):
                continue
            agg[str(c)] = float(val)
        out.append(
            MetricSummary(
                group=group_enum,
                trial_count=int(row["trial_count"]),
                aggregates=agg,
                notes=[
                    "Source: evaluation_pipeline.comparison_metrics_table "
                    "(same as comparison_metrics.csv metrics)."
                ],
            )
        )
    return out
