from __future__ import annotations

import json
import logging

from flask import Blueprint, jsonify, request, session

from app.services.postgres import get_connection

log_bp = Blueprint("log_bp", __name__)
logger = logging.getLogger(__name__)


def _coerce_int(v):
    if v in (None, ""):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@log_bp.get("/logs")
def list_logs():
    uid_sess = session.get("user_id")
    if uid_sess is None:
        return jsonify({"error": "Authentication required"}), 401
    try:
        effective_uid = int(uid_sess)
    except (TypeError, ValueError):
        return jsonify({"error": "Authentication required"}), 401

    uid_param = _coerce_int(request.args.get("user_id"))
    if uid_param is not None and uid_param != effective_uid:
        logger.warning(
            "GET /logs forbidden: param user_id=%s session user_id=%s",
            uid_param,
            effective_uid,
        )
        return jsonify({"error": "Forbidden"}), 403

    target_host = (request.args.get("target_host") or "").strip().lower()

    params: list = [effective_uid]
    where = ["user_id = %s", "user_id IS NOT NULL"]
    if target_host:
        where.append("LOWER(target_host) = %s")
        params.append(target_host)

    where_sql = " WHERE " + " AND ".join(where)

    query = (
        "SELECT id, timestamp, user_id, session_id, target_host, event_type, raw_line "
        "FROM rl_logs"
        + where_sql
        + " ORDER BY id DESC LIMIT 500"
    )

    out = []
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, tuple(params))
                for row in cur.fetchall():
                    raw_line = row[6] or ""
                    parsed = None
                    try:
                        parsed = json.loads(raw_line)
                    except Exception:
                        parsed = {"raw_line": raw_line}

                    out.append(
                        {
                            "id": int(row[0]),
                            "timestamp": row[1].isoformat() if row[1] else None,
                            "user_id": row[2],
                            "session_id": row[3],
                            "target_host": row[4],
                            "event_type": row[5],
                            "data": parsed,
                        }
                    )
    except Exception as exc:
        logger.exception("GET /logs query failed: %s", exc)
        return jsonify({"error": "Could not load logs."}), 500

    return jsonify({"items": out, "user_id": effective_uid})
