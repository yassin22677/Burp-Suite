# app/services/event_bus.py

from flask import has_request_context, session

from app import socketio
from app.services.rl_ingest import ingest_rl_event


def emit_and_store_event(event_type: str, raw_line: str):
    """Store in rl_logs + rl_event and broadcast (raw_line is source of truth)."""
    data = {"event_type": event_type, "raw_line": raw_line}
    sess = session if has_request_context() else None
    auth_uid = sess.get("user_id") if sess else None
    result = ingest_rl_event(
        data, sess, auth_user_id=auth_uid if auth_uid is not None else None
    )
    if auth_uid is not None:
        socketio.emit(
            "rl_log",
            {"line": result["raw_line"], "session_id": result.get("session_id")},
            to=f"user_{int(auth_uid)}",
        )
    print(raw_line)
