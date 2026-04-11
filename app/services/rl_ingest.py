"""Parse Burp / RL log lines and persist to rl_logs (+ best-effort rl_event)."""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlparse

import psycopg2
from flask import current_app
from sqlalchemy.exc import IntegrityError

from app import db
from app.models.rl_event import RLEvent
from app.models.rl_log import RLLog
from app.models.scan_session import ScanSession
from app.models.user import User

TAG_RE = re.compile(r"\[RL\]\[([A-Z]+)\]")


def infer_event_type(raw_line: str) -> str | None:
    m = TAG_RE.search(raw_line or "")
    return m.group(1) if m else None


def _parse_req(raw_line: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m_rid = re.search(r"\[reqId=(\d+)\]", raw_line)
    if m_rid:
        out["request_id"] = int(m_rid.group(1))
    m = re.search(r"\]\s+([A-Z]+)\s+(https?://\S+)", raw_line)
    if m:
        out["http_method"] = m.group(1)
        url = m.group(2).split()[0].rstrip(")")
        out["url"] = url
        host = urlparse(url).hostname
        if host:
            out["target_host"] = host.lower()
    return out


def _parse_act(raw_line: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m_aid = re.search(r"\[actionId=(\d+)\]", raw_line)
    if m_aid:
        out["request_id"] = int(m_aid.group(1))
    m_val = re.search(r"value=(\d+)", raw_line)
    if m_val:
        v = int(m_val.group(1))
        out["action_id"] = v
        out["action_name"] = f"RL_VALUE_{v}"
    return out


def _parse_apply(raw_line: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m_aid = re.search(r"\[actionId=(\d+)\]", raw_line)
    if m_aid:
        out["action_id"] = int(m_aid.group(1))
    m = re.search(r"\[RL\]\[APPLY\]\[actionId=\d+\]\s+([A-Z0-9_]+)", raw_line)
    if m:
        out["action_name"] = m.group(1)
    murl = re.search(r"(https?://[^\s\)]+)", raw_line)
    if murl:
        out["url"] = murl.group(1).rstrip(")")
        h = urlparse(out["url"]).hostname
        if h:
            out["target_host"] = h.lower()
    return out


def _parse_resp(raw_line: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m_s = re.search(r"status=(\d+)", raw_line)
    if m_s:
        out["status_code"] = int(m_s.group(1))
    m_r = re.search(r"reward=(-?\d+)", raw_line)
    if m_r:
        out["reward"] = int(m_r.group(1))
    return out


def _parse_scan(raw_line: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m_url = re.search(r"url=([^|\s]+)", raw_line)
    if m_url:
        u = m_url.group(1).strip()
        out["url"] = u
        if u.startswith("http"):
            h = urlparse(u).hostname
            if h:
                out["target_host"] = h.lower()
    m_issue = re.search(r"\[issueId=(\d+)\]", raw_line)
    if m_issue:
        out["request_id"] = int(m_issue.group(1))
    m = re.search(r"\[RL\]\[SCAN\][^\]]*\]\s+(.+?)\s*\|", raw_line)
    if m:
        out["action_name"] = m.group(1).strip()[:255]
    return out


def _parse_reward(raw_line: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m = re.search(r"value=(-?\d+)", raw_line)
    if m:
        out["reward"] = int(m.group(1))
    return out


def parse_structured_from_raw(raw_line: str) -> dict[str, Any]:
    et = infer_event_type(raw_line) or ""
    parsers = {
        "REQ": _parse_req,
        "ACT": _parse_act,
        "APPLY": _parse_apply,
        "RESP": _parse_resp,
        "SCAN": _parse_scan,
        "REWARD": _parse_reward,
    }
    fn = parsers.get(et, lambda _: {})
    parsed = fn(raw_line)
    parsed["event_type"] = et or parsed.get("event_type")
    return parsed


def _coerce_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _user_exists(uid: int | None) -> bool:
    """App table is public.users — must match rl_logs FK after migration (see scripts/)."""
    if uid is None:
        return False
    try:
        return (
            db.session.query(User.id).filter(User.id == int(uid)).first() is not None
        )
    except Exception:
        return False


def _is_rl_logs_user_fk_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return "rl_logs" in msg and "user" in msg and (
        "foreign key" in msg or "violates foreign key" in msg
    )


def _insert_rl_log_psycopg_fallback(
    raw_line: str,
    user_id: int,
    session_fk: int | None,
    target_host: str | None,
    event_type: str | None,
) -> None:
    dsn = current_app.config["PG_DSN"]
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO rl_logs
                    (raw_line, user_id, session_id, target_host, event_type)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (raw_line, user_id, session_fk, target_host, event_type),
            )
        conn.commit()
    finally:
        conn.close()


def _infer_session_owner_user_id(session_fk: int | None) -> int | None:
    if session_fk is None:
        return None
    try:
        row = db.session.execute(
            db.text(
                """
                SELECT s.user_id FROM sessions s
                INNER JOIN users u ON u.id = s.user_id
                WHERE s.id = :sid AND s.status = 'active'
                LIMIT 1
                """
            ),
            {"sid": session_fk},
        ).first()
        if row and row[0] is not None:
            return int(row[0])
    except Exception:
        pass
    return None


def _infer_active_session_fk(
    user_id: int | None, target_host: str | None, url: str | None
) -> int | None:
    if user_id is None:
        return None
    params: dict[str, Any] = {"uid": user_id}
    clauses = ["s.user_id = :uid", "s.status = 'active'"]

    host = (target_host or "").strip().lower()
    if not host and url:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
    if host:
        clauses.append("LOWER(s.target_url) LIKE :h")
        params["h"] = f"%{host}%"

    sql = (
        "SELECT s.id FROM sessions s "
        "INNER JOIN users u ON u.id = s.user_id WHERE "
        + " AND ".join(clauses)
        + " ORDER BY s.id DESC LIMIT 1"
    )
    try:
        row = db.session.execute(db.text(sql), params).first()
        if row:
            return int(row[0])
    except Exception:
        pass
    return None


def ingest_rl_event(
    data: dict[str, Any],
    flask_session: Mapping[str, Any] | None = None,
    *,
    auth_user_id: int | None = None,
) -> dict[str, Any]:
    """
    Persist rl_logs (required) and best-effort rl_event.
    Returns dict with raw_line and session_id (stringified integer FK or None).
    """
    raw_line = data.get("raw_line") or data.get("line") or data.get("message")
    if not raw_line:
        et = data.get("event_type")
        action_name = data.get("action_name")
        url = data.get("url")
        if et and (action_name or url):
            raw_line = f"[RL][{et}] {action_name or ''} {url or ''}".strip()
    if not raw_line:
        raise ValueError("raw_line missing")

    structured: dict[str, Any] = {}
    for key in (
        "event_type",
        "request_id",
        "action_id",
        "action_name",
        "url",
        "http_method",
        "status_code",
        "reward",
        "explanation",
        "target_host",
    ):
        if key in data and data[key] is not None:
            structured[key] = data[key]

    parsed = parse_structured_from_raw(raw_line)
    merged: dict[str, Any] = {**parsed, **structured}

    et = merged.get("event_type") or infer_event_type(raw_line)
    target_host = merged.get("target_host") or data.get("target_host")

    if auth_user_id is not None:
        user_id = _coerce_int(auth_user_id)
    else:
        user_id = data.get("user_id")
        if user_id is None and flask_session is not None:
            user_id = flask_session.get("user_id")
        user_id = _coerce_int(user_id)

    session_fk = _coerce_int(data.get("session_id"))
    if user_id is None:
        user_id = _infer_session_owner_user_id(session_fk)

    th = (target_host or "").strip() if target_host else None
    et_store = et[:256] if et else None

    if session_fk is not None and user_id is not None:
        owned_active = (
            db.session.query(ScanSession.id)
            .filter(
                ScanSession.id == session_fk,
                ScanSession.user_id == user_id,
                ScanSession.status == "active",
            )
            .first()
        )
        if not owned_active:
            session_fk = None

    if session_fk is None:
        session_fk = _infer_active_session_fk(user_id, th, merged.get("url"))

    if user_id is not None and not _user_exists(user_id):
        current_app.logger.warning(
            "ingest_rl_event: user_id=%s not found in users (orphan session?); "
            "skipping rl_logs for this line.",
            user_id,
        )
        user_id = None

    if user_id is None:
        current_app.logger.warning(
            "ingest_rl_event: skipped rl_logs insert (user_id required); raw_line prefix=%s",
            (raw_line[:80] + "…") if len(raw_line) > 80 else raw_line,
        )
    else:
        log_row = RLLog(
            raw_line=raw_line,
            user_id=user_id,
            session_id=session_fk,
            target_host=th,
            event_type=et_store,
        )
        try:
            db.session.add(log_row)
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            if _is_rl_logs_user_fk_error(exc):
                current_app.logger.error(
                    "rl_logs FK points at wrong table (e.g. app_users). "
                    "Run scripts/pg_fix_rl_logs_user_fk_to_users.sql — %s",
                    exc,
                )
            else:
                current_app.logger.warning("RLLog insert integrity error: %s", exc)
        except Exception as exc:
            db.session.rollback()
            if _is_rl_logs_user_fk_error(exc):
                current_app.logger.error(
                    "rl_logs user_id FK error — run "
                    "scripts/pg_fix_rl_logs_user_fk_to_users.sql: %s",
                    exc,
                )
            else:
                current_app.logger.warning(
                    "RLLog ORM insert failed, trying psycopg2: %s", exc
                )
                try:
                    _insert_rl_log_psycopg_fallback(
                        raw_line, user_id, session_fk, th, et_store
                    )
                except Exception as exc2:
                    current_app.logger.error("rl_logs insert failed: %s", exc2)

    rid = _coerce_int(merged.get("request_id"))
    aid = _coerce_int(merged.get("action_id"))
    sc = _coerce_int(merged.get("status_code"))
    rw = _coerce_int(merged.get("reward"))

    action_name = merged.get("action_name")
    if action_name is not None:
        action_name = str(action_name)[:255] or None

    evt_type = (et[:64] if et else None) or "UNKNOWN"

    evt = RLEvent(
        timestamp=db.func.now(),
        event_type=evt_type,
        request_id=rid,
        action_id=aid,
        action_name=action_name,
        url=merged.get("url"),
        http_method=(
            str(merged.get("http_method"))[:32] if merged.get("http_method") else None
        ),
        status_code=sc,
        reward=rw,
        explanation=merged.get("explanation"),
        raw_line=raw_line,
    )
    try:
        db.session.add(evt)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("rl_event insert skipped (schema mismatch OK): %s", exc)

    out_sid = str(session_fk) if session_fk is not None else None
    return {"raw_line": raw_line, "session_id": out_sid}
