from flask import Blueprint, request, jsonify
from app import db, socketio
from app.models.rl_log import RLLog

rl_event_bp = Blueprint("rl_event_bp", __name__)

@rl_event_bp.route("/api/rl-events", methods=["POST"])
def receive_rl_event():
    data = request.get_json(silent=True) or {}

    # Accept multiple possible keys from extension/tools
    raw_line = data.get("raw_line") or data.get("line") or data.get("message")

    # If extension sends structured fields, build a line
    if not raw_line:
        event_type = data.get("event_type")
        action_name = data.get("action_name")
        url = data.get("url")
        if event_type and (action_name or url):
            raw_line = f"[RL][{event_type}] {action_name or ''} {url or ''}".strip()

    if not raw_line:
        return jsonify({"error": "raw_line missing"}), 400

    log = RLLog(raw_line=raw_line)
    db.session.add(log)
    db.session.commit()

    # Broadcast to ALL connected dashboards
    socketio.emit("rl_log", {"line": raw_line})


    return jsonify({"status": "ok"}), 200
