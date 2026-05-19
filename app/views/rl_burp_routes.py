"""
RL HTTP endpoints called by the Burp Montoya extension.

RLHttpClient.decideAction expects a **plain text** body with a single integer 0..4.

State encoding (5-tuple fed to QLearningAgent)
----------------------------------------------
  (response_class, method_bucket, url_length_bucket, scan_speed, fp_rate)

  response_class   : 0=2xx  1=3xx  2=4xx  3=5xx  4=other
  method_bucket    : 0=GET  1=POST  2=other
  url_length_bucket: 0=short(<50)  1=medium(50-200)  2=long(>200)
  scan_speed       : 0 (placeholder — no live signal yet)
  fp_rate          : 0 (placeholder — no live signal yet)

Action index ↔ name mapping (kept stable; Burp extension uses the integer)
---------------------------------------------------------------------------
  0 = NO_OP
  1 = ENABLE_INTERCEPT
  2 = DISABLE_INTERCEPT
  3 = ENABLE_ACTIVE_SCAN
  4 = DISABLE_ACTIVE_SCAN
"""

from __future__ import annotations

import logging

from flask import Blueprint, Response, jsonify, request

from app.services.rl_agent import agent

logger = logging.getLogger(__name__)

rl_burp_bp = Blueprint("rl_burp", __name__)

# Stable integer ↔ string mapping shared between decide and update.
# Order matters: index 0..4 must stay fixed so the Burp extension keeps working.
ACTION_NAMES: list[str] = [
    "NO_OP",             # 0
    "ENABLE_INTERCEPT",  # 1
    "DISABLE_INTERCEPT", # 2
    "ENABLE_ACTIVE_SCAN",  # 3
    "DISABLE_ACTIVE_SCAN", # 4
]
_NAME_TO_IDX = {name: idx for idx, name in enumerate(ACTION_NAMES)}

# Last (state, action_name) seen — used by /update-reward to close the learning loop.
# Single global is fine: the Burp extension sends decide → reward pairs sequentially.
_last_state: tuple | None = None
_last_action: str | None = None


def _build_state(data: dict) -> tuple:
    """Map raw request fields to a hashable 5-int state tuple."""
    # response_class
    try:
        status = int(data.get("status", 0))
    except (TypeError, ValueError):
        status = 0
    if 200 <= status < 300:
        rc = 0
    elif 300 <= status < 400:
        rc = 1
    elif 400 <= status < 500:
        rc = 2
    elif 500 <= status < 600:
        rc = 3
    else:
        rc = 4

    # method_bucket
    method = (data.get("method") or "").upper()
    mb = 0 if method == "GET" else (1 if method == "POST" else 2)

    # url_length_bucket
    url = data.get("url") or ""
    url_len = len(url)
    try:
        url_len = int(data.get("url_length", url_len) or url_len)
    except (TypeError, ValueError):
        pass
    ulb = 0 if url_len < 50 else (1 if url_len <= 200 else 2)

    return (rc, mb, ulb, 0, 0)


@rl_burp_bp.post("/decide-action")
def decide_action():
    global _last_state, _last_action

    data = request.get_json(silent=True) or {}
    state = _build_state(data)

    action_name = agent.decide_action(state)
    action_idx = _NAME_TO_IDX.get(action_name, 0)

    _last_state = state
    _last_action = action_name

    logger.debug(
        "decide-action state=%s → %s (idx=%s) epsilon=%.3f states=%s",
        state, action_name, action_idx, agent.epsilon, len(agent.q_table),
    )

    return Response(str(action_idx), mimetype="text/plain")


@rl_burp_bp.post("/update-reward")
def update_reward():
    global _last_state, _last_action

    data = request.get_json(silent=True) or {}
    try:
        reward = float(data.get("reward", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid reward"}), 400

    if _last_state is not None and _last_action is not None:
        # Build next state from the current request data (if provided), otherwise
        # reuse the last state as a terminal self-transition.
        next_state = _build_state(data) if data.get("status") else _last_state
        agent.update(_last_state, _last_action, reward, next_state)
        agent.decay_epsilon()
        logger.debug(
            "update-reward state=%s action=%s reward=%s → next=%s epsilon=%.3f",
            _last_state, _last_action, reward, next_state, agent.epsilon,
        )
    else:
        logger.debug("update-reward: no pending state/action to update (first call)")

    return jsonify({"status": "ok", "states_trained": len(agent.q_table)})
