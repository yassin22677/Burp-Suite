import logging
from urllib.parse import urlparse

import psycopg2
from flask import Blueprint, jsonify, request
from psycopg2.extras import Json

from app.services.api_auth import resolve_scan_actor_user_id
from app.services.postgres import get_connection, pg_errors

scan_session_bp = Blueprint("scan_session", __name__, url_prefix="/api/scan")

logger = logging.getLogger(__name__)


def _resolve_website_base_url(user_id: int, website_id: int) -> str | None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT base_url FROM websites
                WHERE id = %s AND user_id = %s
                """,
                (website_id, user_id),
            )
            row = cur.fetchone()
            if not row or not row[0]:
                return None
            return str(row[0]).strip()


def _default_token_for_user(user_id: int) -> tuple[str | None, dict | None]:
    """
    If token fields are omitted by client, auto-fill from users.api_token as
    header Bearer credentials.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "SELECT COALESCE(api_token, '') FROM users WHERE id = %s",
                    (user_id,),
                )
            except Exception:
                conn.rollback()
                return None, None
            row = cur.fetchone()
            tok = (row[0] if row else "") or ""
            tok = str(tok).strip()
            if not tok:
                return None, None
            return "header", {"Authorization": f"Bearer {tok}"}


def _ensure_website_row(user_id: int, target_url: str) -> None:
    base = (target_url or "").strip()
    if not base:
        logger.warning("website ensure skipped: empty base_url user_id=%s", user_id)
        return
    host = (urlparse(base).hostname or "").lower()
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id FROM websites
                    WHERE user_id = %s AND LOWER(base_url) = LOWER(%s)
                    LIMIT 1
                    """,
                    (user_id, base),
                )
                if cur.fetchone():
                    return
                env = (
                    "test"
                    if any(x in host for x in ("test", "staging", "dev", "localhost"))
                    else "prod"
                )
                cur.execute(
                    """
                    INSERT INTO websites (user_id, base_url, environment)
                    VALUES (%s, %s, %s)
                    """,
                    (user_id, base, env),
                )
                logger.info(
                    "website created user_id=%s base_url=%s environment=%s",
                    user_id,
                    base,
                    env,
                )
    except Exception as exc:
        logger.exception(
            "website insert failed user_id=%s base_url=%s: %s", user_id, base, exc
        )
        raise


def upsert_session_row(
    user_id: int,
    target_url: str,
    token_type: str,
    token_value: dict,
) -> int:
    """
    One logical session per (user_id, target_url): update tokens and reactivate
    if a row already exists; otherwise insert.
    """
    target_url = (target_url or "").strip()
    token_type = (token_type or "").strip().lower()
    if not target_url:
        raise ValueError("target_url is required")
    if token_type not in ("cookie", "header"):
        raise ValueError("token_type must be 'cookie' or 'header'")
    if not isinstance(token_value, dict) or not token_value:
        raise ValueError("token_value must be a non-empty JSON object")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM sessions
                WHERE user_id = %s AND target_url = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (user_id, target_url),
            )
            row = cur.fetchone()
            if row:
                sid = int(row[0])
                cur.execute(
                    """
                    UPDATE sessions
                    SET token_type = %s,
                        token_value = %s,
                        status = %s,
                        ended_at = NULL
                    WHERE id = %s AND user_id = %s
                    """,
                    (token_type, Json(token_value), "active", sid, user_id),
                )
                logger.info(
                    "scan session updated user_id=%s session_id=%s target_url=%s",
                    user_id,
                    sid,
                    target_url,
                )
                return sid

            cur.execute(
                """
                INSERT INTO sessions (
                    user_id, target_url, token_type, token_value, status
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (user_id, target_url, token_type, Json(token_value), "active"),
            )
            sid = int(cur.fetchone()[0])
            logger.info(
                "scan session created user_id=%s session_id=%s target_url=%s",
                user_id,
                sid,
                target_url,
            )
            return sid


def _backfill_null_session_tokens(user_id: int) -> None:
    """Repair legacy rows where token_type/token_value were never persisted."""
    tt, tv = _default_token_for_user(user_id)
    if tt is None or not tv:
        logger.warning(
            "token backfill skipped: users.api_token empty for user_id=%s", user_id
        )
        return
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE sessions
                    SET token_type = %s, token_value = %s
                    WHERE user_id = %s
                      AND (token_type IS NULL OR token_value IS NULL)
                    """,
                    (tt, Json(tv), user_id),
                )
                if cur.rowcount:
                    logger.info(
                        "backfilled session tokens for %s row(s) user_id=%s",
                        cur.rowcount,
                        user_id,
                    )
    except Exception as exc:
        logger.exception("session token backfill failed user_id=%s: %s", user_id, exc)


def finish_session(session_id: int, user_id: int) -> bool:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE sessions
                SET ended_at = CURRENT_TIMESTAMP, status = %s
                WHERE id = %s AND user_id = %s
                RETURNING id
                """,
                ("completed", session_id, user_id),
            )
            return cur.fetchone() is not None


@scan_session_bp.post("/start")
def start_scan():
    data = request.get_json() or {}
    user_id = resolve_scan_actor_user_id(request, data)
    if user_id is None:
        return jsonify({"error": "Authentication required"}), 401

    uid = int(user_id)
    target_url = (data.get("target_url") or "").strip()
    token_type = (data.get("token_type") or "").strip().lower() or None
    token_value = data.get("token_value")
    website_id = data.get("website_id")

    if website_id is not None:
        try:
            wid = int(website_id)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid website_id"}), 400
        resolved = _resolve_website_base_url(uid, wid)
        if not resolved:
            return jsonify({"error": "Website not found for this user"}), 404
        target_url = resolved
    elif not target_url:
        # Burp extension default — still a non-null target_url string.
        target_url = "https://burp/active"

    if token_type is not None and token_type not in {"cookie", "header"}:
        return jsonify({"error": "token_type must be 'cookie' or 'header'"}), 400
    if token_type is not None and (not isinstance(token_value, dict) or not token_value):
        return jsonify({"error": "token_value must be a non-empty JSON object"}), 400

    if token_type is None or token_value is None:
        token_type, token_value = _default_token_for_user(uid)

    if (
        token_type is None
        or token_value is None
        or not isinstance(token_value, dict)
        or not token_value
    ):
        return (
            jsonify(
                {
                    "error": (
                        "Session token required: pass token_type ('cookie' or 'header') "
                        "and token_value (JSON object), or set users.api_token for a "
                        "default Bearer header."
                    )
                }
            ),
            400,
        )

    try:
        session_id = upsert_session_row(
            uid, target_url, token_type, token_value
        )
    except pg_errors.UndefinedColumn as exc:
        logger.error("sessions table missing token columns: %s", exc)
        return (
            jsonify(
                {
                    "error": (
                        "Database schema out of date: run scripts/pg_add_session_tokens.sql"
                    )
                }
            ),
            503,
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except psycopg2.OperationalError:
        return (
            jsonify({"error": "Database unavailable. Please try again later."}),
            503,
        )
    except psycopg2.Error as exc:
        logger.exception("scan session upsert failed: %s", exc)
        return jsonify({"error": "Could not create scan session."}), 500

    try:
        _ensure_website_row(uid, target_url)
    except psycopg2.Error:
        return (
            jsonify({"error": "Could not persist website row for this target."}),
            500,
        )

    _backfill_null_session_tokens(uid)

    return (
        jsonify(
            {
                "session_id": session_id,
                "target_url": target_url,
                "user_id": uid,
            }
        ),
        201,
    )


@scan_session_bp.post("/finish")
def finish_scan():
    data = request.get_json() or {}
    user_id = resolve_scan_actor_user_id(request, data)
    if user_id is None:
        return jsonify({"error": "Authentication required"}), 401

    session_id = data.get("session_id")
    if session_id is None:
        return jsonify({"error": "Missing session_id"}), 400

    try:
        session_id_int = int(session_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid session_id"}), 400

    try:
        ok = finish_session(session_id_int, user_id)
    except psycopg2.OperationalError:
        return (
            jsonify({"error": "Database unavailable. Please try again later."}),
            503,
        )

    if not ok:
        return jsonify({"error": "Session not found"}), 404

    return (
        jsonify({"message": "session completed", "session_id": session_id_int}),
        200,
    )
