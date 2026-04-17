"""Resolve dashboard user from API token (Burp / external clients)."""

from __future__ import annotations

from flask import Request, current_app


def extract_bearer_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        t = auth[7:].strip()
        return t or None
    return None


def _coerce_user_id(val) -> int | None:
    if val is None:
        return None
    try:
        u = int(val)
        return u if u > 0 else None
    except (TypeError, ValueError):
        return None


def trusted_loopback(request: Request) -> bool:
    try:
        if not current_app.config.get("RL_TRUST_LOOPBACK_USER_ID", True):
            return False
    except RuntimeError:
        return True
    addr = (request.remote_addr or "").strip().lower()
    if not addr:
        return False
    if addr in ("127.0.0.1", "::1", "localhost"):
        return True
    if addr.startswith("127."):
        return True
    return addr.endswith("127.0.0.1")


def user_id_for_api_token(token: str | None) -> int | None:
    if not token or not token.strip():
        return None
    token = token.strip()
    try:
        from app.services.postgres import get_connection

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM users WHERE api_token = %s LIMIT 1",
                    (token,),
                )
                row = cur.fetchone()
                return int(row[0]) if row else None
    except Exception as exc:
        try:
            current_app.logger.warning(
                "api_token DB lookup failed (run scripts/pg_align_sessions_and_tokens.sql if "
                "users.api_token is missing): %s",
                exc,
            )
        except RuntimeError:
            pass
        return None


def resolve_rl_actor_user_id(request: Request, body: dict) -> int | None:
    """
    Identify caller for POST /api/rl-events: Bearer, JSON api_token, (loopback) JSON user_id,
    then Flask session cookie — so Burp's token is not overridden by a browser session.
    """
    bearer = extract_bearer_token(request)
    if bearer is not None:
        uid = user_id_for_api_token(bearer)
        if uid is not None:
            return uid

    tok = (body.get("api_token") or "").strip()
    if tok:
        uid = user_id_for_api_token(tok)
        if uid is not None:
            return uid

    # Loopback JSON user_id before browser cookie so Burp isn't overridden by a stale dashboard session.
    if trusted_loopback(request):
        uid = _coerce_user_id(body.get("user_id"))
        if uid is not None:
            return uid

    from flask import session as flask_session

    cookie_uid = flask_session.get("user_id")
    if cookie_uid is not None:
        return int(cookie_uid)

    return None


def resolve_scan_actor_user_id(request: Request, body: dict | None) -> int | None:
    """Same rules as rl-events for POST /api/scan/start (Bearer, api_token, loopback user_id, cookie)."""
    body = body or {}
    bearer = extract_bearer_token(request)
    if bearer is not None:
        uid = user_id_for_api_token(bearer)
        if uid is not None:
            return uid
    tok = (body.get("api_token") or "").strip()
    if tok:
        uid = user_id_for_api_token(tok)
        if uid is not None:
            return uid

    if trusted_loopback(request):
        uid = _coerce_user_id(body.get("user_id"))
        if uid is not None:
            return uid

    from flask import session as flask_session

    cookie_uid = flask_session.get("user_id")
    if cookie_uid is not None:
        return int(cookie_uid)

    return None
