"""Session access helpers using existing sessions table columns."""

from __future__ import annotations

import json
from typing import Any

from app.services.postgres import get_connection


def _normalize_json_value(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        try:
            out = json.loads(s)
            return out if isinstance(out, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def fetch_session_row(user_id: int, target_url: str) -> dict[str, Any] | None:
    """Find session by (user_id, target_url): prefer active row, else latest."""
    target_url = (target_url or "").strip()
    with get_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    SELECT id, user_id, target_url, token_type, token_value, status
                    FROM sessions
                    WHERE user_id = %s AND target_url = %s AND status = %s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (user_id, target_url, "active"),
                )
                row = cur.fetchone()
                if row:
                    pass
                else:
                    cur.execute(
                        """
                        SELECT id, user_id, target_url, token_type, token_value, status
                        FROM sessions
                        WHERE user_id = %s AND target_url = %s
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (user_id, target_url),
                    )
                    row = cur.fetchone()
            except Exception:
                conn.rollback()
                cur.execute(
                    """
                    SELECT id, user_id, target_url, NULL AS token_type, NULL AS token_value, status
                    FROM sessions
                    WHERE user_id = %s AND target_url = %s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (user_id, target_url),
                )
                row = cur.fetchone()
            if not row:
                return None
            return {
                "id": int(row[0]),
                "user_id": int(row[1]) if row[1] is not None else None,
                "target_url": row[2],
                "token_type": row[3],
                "token_value": _normalize_json_value(row[4]),
                "status": row[5],
            }


def get_session_auth(user_id: int, target_url: str) -> dict[str, Any] | None:
    """
    Fetch auth token configuration from sessions table and normalize to:
    {"type": "cookie" | "header", "value": {...}}
    """
    session_row = fetch_session_row(user_id=user_id, target_url=target_url)
    if not session_row:
        return None

    token_type = (session_row.get("token_type") or "").strip().lower()
    if token_type not in {"cookie", "header"}:
        return None

    return {"type": token_type, "value": session_row.get("token_value") or {}}


def mark_session_expired(session_id: int) -> None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET status = %s WHERE id = %s",
                ("expired", session_id),
            )
