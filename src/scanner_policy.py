"""
Offline **scanner configuration policy** presets (lab / thesis evaluation).

**Supported today (this module)**

- A **finite catalog** of named scan-policy presets with explainable fields
  (audit depth, throttle posture, false-positive bias). These are **abstract**:
  they do not call Burp Suite or open sockets.
- **Pluggable selectors** (:class:`HeuristicScannerPolicySelector`,
  :class:`RoundRobinScannerPolicySelector`) that return a :class:`ScannerPolicyDecision`
  with an explicit rationale trace for logging and analysis.

**Not supported here (explicitly out of scope for this Python package)**

- Applying configurations inside Burp (Montoya ``AuditConfiguration``, scanner APIs).
  :attr:`ScanPolicyPreset.montoya_action_hint` is an **optional integer tag** for
  cross-reference with a **separate** Java extension, if you maintain one; this
  repository does **not** perform those API calls or automate Burp.
- Joint RL over **payload strategy** × **scan preset**: :mod:`adaptive_controller` learns
  generator arms; scan preset selection is intentionally **orthogonal** so you can
  log and ablate it without changing bandit state.
- Live false-positive rates from Burp issue export: selectors accept simple numeric
  **signals** you populate from offline metrics or external tools.

Use :class:`ExperimentRunnerConfig`’s ``scanner_policy_selector`` to attach decisions
to each trial batch (see :mod:`experiment_runner`).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from .context_extractor import RequestContext
from .evaluation import ExperimentGroup


class AuditDepth(str, Enum):
    """Coarse audit depth tier (explainable; not a Burp API enum)."""

    PASSIVE_ONLY = "passive_only"
    PASSIVE_AND_LIGHT_ACTIVE = "passive_and_light_active"
    PASSIVE_AND_FULL_ACTIVE = "passive_and_full_active"


class ThrottlePosture(str, Enum):
    """Request-rate posture for scanner-like workloads (abstract)."""

    CONSERVATIVE = "conservative"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class FalsePositiveBias(str, Enum):
    """Whether the preset leans toward recall vs precision (thesis vocabulary)."""

    BALANCED = "balanced"
    FAVOR_PRECISION = "favor_precision"
    FAVOR_RECALL = "favor_recall"


@dataclass(frozen=True)
class ScanPolicyPreset:
    """
    One **named** scanner policy preset.

    Fields are documentation-first: they drive explainability and export logs, not
    live Burp wiring. ``montoya_action_hint`` aligns *conceptually* with the demo
    extension’s integer actions (e.g. passive vs active audit) when present.
    """

    preset_id: str
    title: str
    description: str
    audit_depth: AuditDepth
    throttle: ThrottlePosture
    fp_bias: FalsePositiveBias
    montoya_action_hint: int | None = None
    notes: str = ""

    def to_summary_dict(self) -> dict[str, Any]:
        """Compact JSON-friendly snapshot for ``metadata_log`` / trial tags."""
        return {
            "preset_id": self.preset_id,
            "title": self.title,
            "audit_depth": self.audit_depth.value,
            "throttle": self.throttle.value,
            "fp_bias": self.fp_bias.value,
            "montoya_action_hint": self.montoya_action_hint,
        }


# ---------------------------------------------------------------------------
# Finite catalog (extend by adding entries — keep IDs stable for experiments)
# ---------------------------------------------------------------------------

SCAN_POLICY_PRESETS: dict[str, ScanPolicyPreset] = {
    "passive_conservative": ScanPolicyPreset(
        preset_id="passive_conservative",
        title="Passive conservative",
        description=(
            "Passive checks only, conservative rate, precision-leaning heuristic "
            "for noisy targets or early baselines."
        ),
        audit_depth=AuditDepth.PASSIVE_ONLY,
        throttle=ThrottlePosture.CONSERVATIVE,
        fp_bias=FalsePositiveBias.FAVOR_PRECISION,
        montoya_action_hint=3,
        notes="Aligns with passive-audit style actions in the Montoya demo applier.",
    ),
    "balanced_audit": ScanPolicyPreset(
        preset_id="balanced_audit",
        title="Balanced passive + active",
        description=(
            "Default lab narrative: passive coverage plus light active probing; "
            "balanced FP/FN trade-off for structured comparison runs."
        ),
        audit_depth=AuditDepth.PASSIVE_AND_LIGHT_ACTIVE,
        throttle=ThrottlePosture.STANDARD,
        fp_bias=FalsePositiveBias.BALANCED,
        montoya_action_hint=4,
        notes="Maps conceptually to active audit checks in the reference extension.",
    ),
    "active_thorough": ScanPolicyPreset(
        preset_id="active_thorough",
        title="Thorough active",
        description=(
            "Deeper active-style audit posture (abstract); higher throughput; "
            "recall-leaning — use only on authorized narrow scopes."
        ),
        audit_depth=AuditDepth.PASSIVE_AND_FULL_ACTIVE,
        throttle=ThrottlePosture.AGGRESSIVE,
        fp_bias=FalsePositiveBias.FAVOR_RECALL,
        montoya_action_hint=4,
        notes="Same Montoya hint as balanced in the demo; distinguish in thesis by throttle/fp_bias.",
    ),
    "fp_reduction_strict": ScanPolicyPreset(
        preset_id="fp_reduction_strict",
        title="False-positive reduction",
        description=(
            "Emphasize precision and slower sends to reduce scanner noise; "
            "matches project goals around lowering false positives offline."
        ),
        audit_depth=AuditDepth.PASSIVE_ONLY,
        throttle=ThrottlePosture.CONSERVATIVE,
        fp_bias=FalsePositiveBias.FAVOR_PRECISION,
        montoya_action_hint=3,
        notes="Use when adaptive layer sets prefer_fp_reduction or equivalent signal.",
    ),
    "throttle_passive": ScanPolicyPreset(
        preset_id="throttle_passive",
        title="Rate-limited passive",
        description=(
            "Passive-only with strongest throttling; for replay traces with many "
            "429/503 signals or fragile lab targets."
        ),
        audit_depth=AuditDepth.PASSIVE_ONLY,
        throttle=ThrottlePosture.CONSERVATIVE,
        fp_bias=FalsePositiveBias.BALANCED,
        montoya_action_hint=3,
        notes="Select when recent_429_rate (or similar) exceeds a threshold.",
    ),
}


def get_scan_policy_preset(preset_id: str) -> ScanPolicyPreset:
    """Return a catalog entry or raise ``KeyError``."""
    return SCAN_POLICY_PRESETS[preset_id]


def list_scan_policy_preset_ids() -> tuple[str, ...]:
    """Stable ordering for round-robin and documentation."""
    return tuple(sorted(SCAN_POLICY_PRESETS.keys()))


@dataclass
class ScannerPolicySignals:
    """
    Optional **offline** inputs for heuristic selection.

    Populate from your harness (e.g. rolling rate of 429 from replay CSV, or a
    boolean “user asked for FP reduction”). Defaults preserve the balanced preset.
    """

    prefer_fp_reduction: bool = False
    recent_429_rate: float = 0.0
    suggest_active_deep_scan: bool = False


@dataclass(frozen=True)
class RationaleStep:
    """One explainable line in the configuration decision trace."""

    step: str
    detail: str


@dataclass(frozen=True)
class ScannerPolicyDecision:
    """Outcome of a selector: which preset and why."""

    preset_id: str
    rationale: tuple[RationaleStep, ...]
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _ = get_scan_policy_preset(self.preset_id)  # validate id

    def to_log_dict(self) -> dict[str, Any]:
        """Merge-friendly dict for :class:`experiment_runner.ExperimentRunner` logs."""
        preset = get_scan_policy_preset(self.preset_id)
        return {
            "scanner_policy_preset_id": self.preset_id,
            "scanner_policy_summary": preset.to_summary_dict(),
            "scanner_policy_rationale": [{"step": s.step, "detail": s.detail} for s in self.rationale],
            "scanner_policy_context": dict(self.context),
        }


class ScannerPolicySelector(ABC):
    """Abstract configuration-selection model over :data:`SCAN_POLICY_PRESETS`."""

    @abstractmethod
    def select(
        self,
        ctx: RequestContext,
        *,
        experiment_group: ExperimentGroup,
        round_index: int | None = None,
        strategy_arm_label: str | None = None,
    ) -> ScannerPolicyDecision:
        """Choose a preset for this batch; strategy arm is optional metadata only."""


class HeuristicScannerPolicySelector(ScannerPolicySelector):
    """
    Deterministic rules over :class:`ScannerPolicySignals` + light context.

    **Separate from payload arms:** ``strategy_arm_label`` is recorded for analysis
    only; it does not change the rule order unless you extend this class.
    """

    def __init__(self, signals: ScannerPolicySignals | None = None) -> None:
        self.signals = signals or ScannerPolicySignals()

    def select(
        self,
        ctx: RequestContext,
        *,
        experiment_group: ExperimentGroup,
        round_index: int | None = None,
        strategy_arm_label: str | None = None,
    ) -> ScannerPolicyDecision:
        _ = ctx  # reserved for future path/method rules
        sig = self.signals
        rationale: list[RationaleStep] = [
            RationaleStep(
                "signals",
                f"prefer_fp_reduction={sig.prefer_fp_reduction}, "
                f"recent_429_rate={sig.recent_429_rate:.3f}, "
                f"suggest_active_deep_scan={sig.suggest_active_deep_scan}",
            ),
            RationaleStep(
                "experiment_group",
                f"arm={experiment_group.value}, round_index={round_index}, "
                f"strategy_arm={strategy_arm_label!r} (orthogonal to scan preset)",
            ),
        ]

        if sig.suggest_active_deep_scan:
            rationale.append(
                RationaleStep("rule_active", "suggest_active_deep_scan → active_thorough")
            )
            pid = "active_thorough"
        elif sig.prefer_fp_reduction:
            rationale.append(
                RationaleStep("rule_fp", "prefer_fp_reduction → fp_reduction_strict")
            )
            pid = "fp_reduction_strict"
        elif sig.recent_429_rate > 0.2:
            rationale.append(
                RationaleStep("rule_throttle", "recent_429_rate>0.2 → throttle_passive")
            )
            pid = "throttle_passive"
        else:
            rationale.append(RationaleStep("rule_default", "default → balanced_audit"))
            pid = "balanced_audit"

        return ScannerPolicyDecision(
            preset_id=pid,
            rationale=tuple(rationale),
            context={
                "experiment_group": experiment_group.value,
                "round_index": round_index,
                "strategy_arm_label": strategy_arm_label,
            },
        )


class RoundRobinScannerPolicySelector(ScannerPolicySelector):
    """Cycles through a fixed preset list (ablations / reproducible rotation)."""

    def __init__(self, preset_ids: Sequence[str] | None = None) -> None:
        ids = tuple(preset_ids) if preset_ids is not None else list_scan_policy_preset_ids()
        for p in ids:
            get_scan_policy_preset(p)
        self._ids = ids
        self._cursor = 0

    def select(
        self,
        ctx: RequestContext,
        *,
        experiment_group: ExperimentGroup,
        round_index: int | None = None,
        strategy_arm_label: str | None = None,
    ) -> ScannerPolicyDecision:
        _ = ctx
        idx = self._cursor % len(self._ids)
        pid = self._ids[idx]
        self._cursor += 1
        rationale = (
            RationaleStep(
                "round_robin",
                f"position {idx} of {len(self._ids)} (cursor after increment={self._cursor})",
            ),
            RationaleStep(
                "experiment_group",
                f"arm={experiment_group.value}, round_index={round_index}, "
                f"strategy_arm={strategy_arm_label!r}",
            ),
        )
        return ScannerPolicyDecision(
            preset_id=pid,
            rationale=rationale,
            context={
                "round_robin_index": idx,
                "experiment_group": experiment_group.value,
            },
        )


def attach_decision_to_trial_tags(trial_tags: dict[str, Any], decision: ScannerPolicyDecision) -> None:
    """Merge scanner policy fields into existing ``TrialRecord.tags`` (in-place)."""
    for k, v in decision.to_log_dict().items():
        trial_tags[k] = v
