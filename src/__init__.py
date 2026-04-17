"""
Offline / manual Burp-assisted payload generation and evaluation (graduation project).

Python covers retrieval, deterministic hybrid generation, validation, ranking, optional
offline adaptive strategy selection, and metrics on **saved** Burp Intruder exports.
No live Burp API, Intruder automation, or LLM backends in this package.

Submodules: ``context_extractor``, ``payload_validator``, ``evaluation``,
``evaluation_pipeline``, ``execution_backend``, ``experiment_runner``,
``burp_bridge`` (manual file hand-offs),
``payload_generator`` (hybrid generator and optional ranker re-exports),
``payload_ranker``, ``scanner_policy`` (offline preset labels for logging),
``seed_retrieval``, ``adaptive_controller``.
"""

from . import (
    adaptive_controller,
    burp_bridge,
    context_extractor,
    evaluation,
    evaluation_pipeline,
    execution_backend,
    experiment_runner,
    lab_arms,
    payload_generator,
    payload_ranker,
    payload_validator,
    scanner_policy,
    seed_retrieval,
)

__all__ = [
    "context_extractor",
    "payload_validator",
    "evaluation",
    "evaluation_pipeline",
    "execution_backend",
    "experiment_runner",
    "lab_arms",
    "burp_bridge",
    "payload_generator",
    "payload_ranker",
    "scanner_policy",
    "seed_retrieval",
    "adaptive_controller",
]
