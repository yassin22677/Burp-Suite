from flask import Blueprint, request, jsonify
from app.models import db
from app.models.rl_event import RLEvent
from app.services.rl_agent import agent  # IMPORTANT: use the global agent

rl_event_bp = Blueprint("rl_event_bp", __name__)

# ============================================================
# DECIDE ACTION
# ============================================================
@rl_event_bp.route("/decide-action", methods=["POST"])
def decide_action():
    data = request.get_json()

    # Build state tuple EXACTLY as your agent expects
    state = (
        int(data["response_class"]),
        int(data["scan_speed"]),
        int(data["confidence"]),
        int(data["issue_volume"]),
        int(data["false_positive_rate"]),
    )

    # ✅ THIS RETURNS STRING (NOT INT)
    action_name = agent.decide_action(state)

    event = RLEvent(
        event_type="DECIDE",
        action_name=action_name,
        url=data.get("url"),
        http_method=data.get("method"),
        raw_line=str(data)
    )

    db.session.add(event)
    db.session.commit()

    print(f"[DB] INSERTED DECIDE action_name={action_name}")

    return jsonify({
        "action_name": action_name
    }), 200


# ============================================================
# UPDATE REWARD
# ============================================================
@rl_event_bp.route("/update-reward", methods=["POST"])
def update_reward():
    data = request.get_json()

    reward = int(data.get("reward", 0))
    action_name = data.get("action_name")  # STRING, not ID

    event = RLEvent(
        event_type="REWARD",
        action_name=action_name,
        reward=reward,
        raw_line=str(data)
    )

    db.session.add(event)
    db.session.commit()

    print(f"[DB] INSERTED REWARD action_name={action_name} reward={reward}")

    return jsonify({"status": "ok"}), 200
