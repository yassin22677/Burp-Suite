"""
Contextual bandit controller for **strategy selection** (experiment arm **D**, lab evaluation).

This module chooses **which discrete strategy** (payload family and generator mode)
to apply next. It **does not** synthesize payload strings and imports **no**
generator implementation, by design: the thesis can describe **policy learning**
(:math:`\\pi(a \\mid x)`) separately from **payload synthesis** under a fixed policy.
**Scanner-style configuration presets** (passive vs active posture, throttle, FP bias) in
:mod:`scanner_policy` are a separate orthogonal **documentation / logging** knob; they
do not automate Burp or any scanner—see :class:`~experiment_runner.ExperimentRunner`.

Recommended driver sequence:

1. Featurize :class:`~src.context_extractor.RequestContext` (plus memory).
2. Call :meth:`AdaptiveBanditController.select_strategy` to obtain a :class:`StrategyArm`.
3. Map the arm to ``GenerationRequest`` fields in :mod:`payload_generator` (e.g.
   ``family``, ``options``) and invoke the generation pipeline there.
4. After authorized observation (manual Intruder export or offline replay fixtures),
   populate :class:`OutcomeMetrics`.
5. Call :meth:`AdaptiveBanditController.register_outcome` with the scalar reward.

**Why LinUCB:** Each arm maintains a **linear** reward model in context features with a
**ridge-regularized** least-squares update and an **upper-confidence** exploration
bonus. This class of algorithms is standard in the contextual bandit literature,
admits a concise mathematical description in a dissertation, and avoids ad-hoc
credit assignment across a large MDP when the action is only “which generator
configuration to try” per request context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import numpy as np

from .context_extractor import RequestContext

# ---------------------------------------------------------------------------
# State / action / reward (thesis vocabulary)
# ---------------------------------------------------------------------------
# **State:** ``x = build_context_features(request_context, family_reward_memory)``,
# a fixed-length vector (bias, HTTP method bucket, coarse URL/shape signals, and
# EMA of past rewards per tracked family). This is *not* full MDP state —
# it is the contextual bandit assumption.
#
# **Action:** discrete arm index ``a`` mapping to :class:`StrategyArm`
# ``(family, generator_mode)``. The controller never emits payload text.
#
# **Reward:** ``r = outcome_to_reward(outcome)``, a scalar from :class:`OutcomeMetrics`
# via a prioritized rule block (:class:`RewardPolicy`).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Reward: outcomes → scalar (explicit, thesis-friendly)
# ---------------------------------------------------------------------------


@dataclass
class OutcomeMetrics:
    """
    Raw signals observed **after** issuing a fuzzed request in the lab.

    Populate fields as completely as your harness allows; missing values should
    be ``None`` and are handled conservatively by :func:`outcome_to_reward`.
    """

    baseline_status_code: int | None = None
    trial_status_code: int | None = None
    baseline_length: int | None = None
    trial_length: int | None = None
    strong_abnormal: bool = False
    moderate_differential: bool = False
    invalid_candidate_batch: bool = False


@dataclass
class RewardPolicy:
    """
    Maps prioritized outcome classes to scalar rewards.

    Priority order (first match wins — easy to explain, avoids double-counting):
    1. ``invalid_candidate_batch``
    2. ``strong_abnormal``
    3. ``moderate_differential``
    4. default (no meaningful change)
    """

    invalid_batch: float = -1.0
    strong_abnormal: float = 1.0
    moderate_differential: float = 0.35
    no_change: float = -0.05


def outcome_to_reward(
    outcome: OutcomeMetrics,
    policy: RewardPolicy | None = None,
) -> float:
    """
    Turn lab observations into one bandit reward in [-1, 1] scale (typical tuning).

    **Strong abnormal** is expected to be set by your harness when responses are
    clearly anomalous (e.g. error class change, security-specific markers). This
    module does **not** define “abnormal” thresholds — you set flags explicitly
    so the thesis methodology stays transparent.
    """
    p = policy or RewardPolicy()
    if outcome.invalid_candidate_batch:
        return p.invalid_batch
    if outcome.strong_abnormal:
        return p.strong_abnormal
    if outcome.moderate_differential:
        return p.moderate_differential
    return p.no_change


# ---------------------------------------------------------------------------
# Action space: discrete “strategies” (no payload generation here)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StrategyArm:
    """
    One bandit **arm**: a policy for the downstream generator, not a payload.

    Example arms for group **D**:
    - (family=sql, mode=hybrid)
    - (family=xss, mode=hybrid)
    - (family=sql, mode=template)
    """

    index: int
    family: str
    generator_mode: str

    @property
    def label(self) -> str:
        """Compact string for logs / thesis tables."""
        return f"{self.family}:{self.generator_mode}"


@dataclass(frozen=True)
class BanditDecision:
    """
    Output of selection step: which arm to play plus diagnostics for explainability.
    """

    arm: StrategyArm
    ucb_scores: tuple[float, ...]
    context_features: tuple[float, ...]


# ---------------------------------------------------------------------------
# State: context features + lightweight memory of past rewards by family
# ---------------------------------------------------------------------------


@dataclass
class FamilyRewardMemory:
    """
    Tracks an exponential moving average (EMA) of **rewards** per payload family.

    This is *not* part of LinUCB's internal matrices; it is extra state your thesis
    can cite as “prior family success history” features fed into the context vector.
    """

    decay: float = 0.9
    ema_by_family: dict[str, float] = field(default_factory=dict)

    def update(self, family: str, reward: float) -> None:
        prev = self.ema_by_family.get(family, 0.0)
        self.ema_by_family[family] = self.decay * prev + (1.0 - self.decay) * reward

    def ema_vector(self, families: Sequence[str]) -> list[float]:
        """Fixed-length vector aligned with ``families`` order."""
        return [float(self.ema_by_family.get(f, 0.0)) for f in families]


def default_method_bucket(method: str) -> tuple[float, float, float]:
    """Returns one-hot-like triple (is_get, is_post, is_other) for the context vector."""
    m = (method or "").upper()
    if m == "GET":
        return 1.0, 0.0, 0.0
    if m == "POST":
        return 0.0, 1.0, 0.0
    return 0.0, 0.0, 1.0


def build_context_features(
    ctx: RequestContext,
    memory: FamilyRewardMemory,
    tracked_families: Sequence[str] = ("sql", "xss", "cmd", "encoded_attack", "other"),
) -> np.ndarray:
    """
    Map :class:`RequestContext` + memory to a fixed-length vector ``x ∈ R^d``.

    **Thesis note:** This function is deliberately simple and inspectable; you can
    replace it with richer NLP or graph features without changing the LinUCB math.
    """
    is_get, is_post, is_other = default_method_bucket(ctx.method)
    n_params = len(ctx.parameter_tags)
    n_params_norm = min(float(n_params) / 10.0, 1.0)
    depth_tokens = ctx.path.strip("/").split("/") if ctx.path else []
    path_depth_norm = min(len(depth_tokens) / 8.0, 1.0)
    ctype = (ctx.content_type or "").lower()
    is_jsonish = 1.0 if "json" in ctype else 0.0
    is_formish = 1.0 if ("form" in ctype) or ("x-www-form-urlencoded" in ctype) else 0.0

    ema = memory.ema_vector(tracked_families)

    vec = [
        1.0,  # bias
        is_get,
        is_post,
        is_other,
        n_params_norm,
        path_depth_norm,
        is_jsonish,
        is_formish,
        *ema,
    ]
    return np.asarray(vec, dtype=float)


def feature_dimension(tracked_families: Sequence[str]) -> int:
    """
    bias (1) + method bucket (3) + structural scalars (4) + EMA per tracked family.

    Structural scalars: normalized parameter count, normalized path depth, JSON-ish
    and form-ish content-type indicators.
    """
    return 8 + len(tuple(tracked_families))


# ---------------------------------------------------------------------------
# LinUCB scaffold (contextual bandit)
# ---------------------------------------------------------------------------


class LinUCB:
    """
    Linear contextual bandit with UCB-style exploration (ridge initialization).

    For each arm *a*, maintain:
    - ``A_a`` — regularized design matrix (starts at ``ridge · I``)
    - ``b_a`` — response-weighted sum of observed contexts
    - ``θ_a = A_a^{-1} b_a`` — estimated linear payoff parameters

    **Selection:** :math:`\\arg\\max_a \\theta_a^\\top x + \\alpha \\sqrt{x^\\top A_a^{-1} x}`.
    The second term grows where uncertainty is large, encouraging exploration.

    This is a textbook-compatible formulation suitable for formal discussion alongside
    :class:`AdaptiveBanditController` and :func:`build_context_features`.
    """

    def __init__(
        self,
        n_arms: int,
        dim: int,
        alpha: float = 0.8,
        ridge: float = 1.0,
    ) -> None:
        if n_arms < 2:
            raise ValueError("LinUCB expects at least 2 arms for adaptive selection.")
        self.n_arms = n_arms
        self.dim = dim
        self.alpha = float(alpha)
        self._ridge = float(ridge)
        self._A: list[np.ndarray] = [
            np.eye(dim, dtype=float) * self._ridge for _ in range(n_arms)
        ]
        self._b: list[np.ndarray] = [np.zeros(dim, dtype=float) for _ in range(n_arms)]

    def _theta(self, arm: int) -> np.ndarray:
        return np.linalg.solve(self._A[arm], self._b[arm])

    def ucb_values(self, x: np.ndarray) -> np.ndarray:
        scores = np.zeros(self.n_arms, dtype=float)
        for a in range(self.n_arms):
            theta = self._theta(a)
            pred = float(theta @ x)
            invA_x = np.linalg.solve(self._A[a], x)
            conf = float(np.sqrt(max(x @ invA_x, 0.0)))
            scores[a] = pred + self.alpha * conf
        return scores

    def select_arm(self, x: np.ndarray) -> tuple[int, np.ndarray]:
        ucb = self.ucb_values(x)
        return int(np.argmax(ucb)), ucb

    def update(self, arm: int, x: np.ndarray, reward: float) -> None:
        self._A[arm] += np.outer(x, x)
        self._b[arm] += reward * x


# ---------------------------------------------------------------------------
# Facade: easy wiring for experiments (group D)
# ---------------------------------------------------------------------------


class AdaptiveBanditController:
    """
    Orchestrates LinUCB updates and optional family-level reward memory.

    **Does not generate payloads.** Emits a :class:`StrategyArm` that the experiment
    driver translates into ``GenerationRequest.family`` and ``options[\"generator_mode\"]``
    (and related seeds/candidate limits)—keeping exploration logic out of :mod:`payload_generator`.
    """

    def __init__(
        self,
        arms: Sequence[StrategyArm],
        tracked_families: Sequence[str] = ("sql", "xss", "cmd", "encoded_attack", "other"),
        reward_policy: RewardPolicy | None = None,
        lin_alpha: float = 0.8,
        memory_decay: float = 0.9,
    ) -> None:
        if not arms:
            raise ValueError("At least one StrategyArm is required.")
        self.arms = tuple(arms)
        self.tracked_families = tuple(tracked_families)
        self.reward_policy = reward_policy or RewardPolicy()
        self.memory = FamilyRewardMemory(decay=memory_decay)
        d = feature_dimension(self.tracked_families)
        self._bandit = LinUCB(n_arms=len(self.arms), dim=d, alpha=lin_alpha)

    def select_strategy(self, ctx: RequestContext) -> BanditDecision:
        x = build_context_features(ctx, self.memory, self.tracked_families)
        idx, ucb = self._bandit.select_arm(x)
        return BanditDecision(
            arm=self.arms[idx],
            ucb_scores=tuple(float(s) for s in ucb),
            context_features=tuple(float(v) for v in x),
        )

    def register_outcome(
        self,
        ctx: RequestContext,
        arm: StrategyArm,
        outcome: OutcomeMetrics,
    ) -> float:
        """
        Update bandit statistics and family EMA from observed lab outcome.

        Returns the numeric reward used for the LinUCB update.
        """
        reward = outcome_to_reward(outcome, self.reward_policy)
        x = build_context_features(ctx, self.memory, self.tracked_families)
        self.memory.update(arm.family, reward)
        self._bandit.update(arm.index, x, reward)
        return float(reward)


def arms_from_grid(
    families: Sequence[str],
    modes: Sequence[str],
) -> tuple[StrategyArm, ...]:
    """Convenience: Cartesian product with stable indices (report reproducibility)."""
    arms: list[StrategyArm] = []
    idx = 0
    for fam in families:
        for mode in modes:
            arms.append(StrategyArm(index=idx, family=fam, generator_mode=mode))
            idx += 1
    return tuple(arms)
