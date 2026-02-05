from flask import Blueprint, request, jsonify
from app import db, socketio
from app.models.rl_log import RLLog

rl_event_bp = Blueprint("rl_event_bp", __name__)

@rl_event_bp.route("/api/rl-events", methods=["POST"])
def receive_rl_event():
    data = request.get_json(silent=True)

    if not data or "raw_line" not in data:
        return jsonify({"error": "raw_line missing"}), 400

    raw_line = data["raw_line"]

    # 1️⃣ SAVE EXACT LINE TO DATABASE
    log = RLLog(raw_line=raw_line)
    db.session.add(log)
    db.session.commit()

    # 2️⃣ STREAM EXACT SAME LINE
    socketio.emit("rl_log", {"line": raw_line})

    return jsonify({"status": "ok"}), 200
