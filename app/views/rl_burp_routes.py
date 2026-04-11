"""
RL HTTP endpoints called by the Burp Montoya extension.

RLHttpClient.decideAction expects a **plain text** body with a single integer 0..4.
"""

from __future__ import annotations

import random

from flask import Blueprint, Response, jsonify, request

rl_burp_bp = Blueprint("rl_burp", __name__)

ACTION_SPACE = 5


@rl_burp_bp.post("/decide-action")
def decide_action():
    data = request.get_json(silent=True) or {}
    try:
        status = int(data.get("status", 0))
    except (TypeError, ValueError):
        status = 0
    method = (data.get("method") or "").upper()
    url = data.get("url") or ""
    url_len = int(data.get("url_length", len(url)) or 0)

    # Deterministic 0..4 from traffic features (replace with QLearningAgent when wired)
    seed = hash((method, url[:200], url_len, status)) & 0x7FFFFFFF
    rng = random.Random(seed)
    action = rng.randint(0, ACTION_SPACE - 1)

    return Response(str(action), mimetype="text/plain")


@rl_burp_bp.post("/update-reward")
def update_reward():
    data = request.get_json(silent=True) or {}
    try:
        _ = int(data.get("reward", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid reward"}), 400
    return jsonify({"status": "ok"})
