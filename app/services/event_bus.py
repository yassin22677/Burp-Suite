# app/services/event_bus.py

from app.models import db
from app.models.rl_event import RLEvent
from app.socketio import socketio


def emit_and_store_event(event_type: str, raw_line: str):
    """
    Hybrid STREAM + STORE
    - raw_line is the SINGLE SOURCE OF TRUTH
    """

    # -------- STORE (PostgreSQL) --------
    row = RLEvent(
        event_type=event_type,
        raw_line=raw_line
    )
    db.session.add(row)
    db.session.commit()

    # -------- STREAM (WebSocket) --------
    socketio.emit("rl_log", {
        "line": raw_line
    })

    # -------- TERMINAL (optional, same line) --------
    print(raw_line)
