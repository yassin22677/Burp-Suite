import time

from flask import Blueprint, current_app, jsonify, request, session
from sqlalchemy import func, or_
from urllib.parse import urlparse
import re

from app import db, socketio
from app.models.rl_event import RLEvent
from app.models.rl_log import RLLog
from app.models.scan_session import ScanSession
from app.models.user import User
from app.services.api_auth import resolve_rl_actor_user_id, trusted_loopback
from app.services.rl_ingest import (
    _coerce_int,
    build_rl_xai_payload,
    ingest_rl_event,
    parse_structured_from_raw,
)

rl_event_bp = Blueprint("rl_event_bp", __name__)

_LOOPBACK_HINT_TTL_SECONDS = 15.0
_loopback_session_hints: dict[str, tuple[float, int, int]] = {}


def _active_session_filter():
    return request.args.get("session_id", type=int)


def _dashboard_user_scope() -> int | None:
    """
    For dashboard polling endpoints, scope logs to the logged-in user when
    a Flask session exists. This prevents cross-account log leakage.
    """
    uid = session.get("user_id")
    try:
        return int(uid) if uid is not None else None
    except (TypeError, ValueError):
        return None


def _host_candidates_from_event(data: dict) -> list[str]:
    """Extract hostname candidates from RL payloads (Burp lines often omit https://)."""
    raw = str(data.get("raw_line") or data.get("line") or data.get("message") or "")
    seen: list[str] = []

    def push(h: str | None) -> None:
        if not h:
            return
        h = h.strip().lower().rstrip(".").split(":")[0]
        if h and h not in seen:
            seen.append(h)

    url = data.get("url")
    if isinstance(url, str) and url.strip():
        try:
            push(urlparse(url.strip()).hostname)
        except Exception:
            pass

    for m in re.finditer(r"(https?://[^\s\)\]]+)", raw):
        try:
            push(urlparse(m.group(1)).hostname)
        except Exception:
            pass

    mh = re.search(r"(?i)Host:\s*([^\]\s,;]+)", raw)
    if mh:
        push(mh.group(1))

    mu = re.search(r"(?i)\burl=([^\s|\]]+)", raw)
    if mu:
        u = mu.group(1).strip()
        if u.startswith("http"):
            try:
                push(urlparse(u).hostname)
            except Exception:
                pass
        else:
            push(u.split("/")[0])

    return seen


def _loopback_hint_key() -> str:
    return (request.remote_addr or "").strip().lower() or "loopback"


def _remember_loopback_session_hint(user_id: int | None, session_id: int | None) -> None:
    if user_id is None or session_id is None:
        return
    _loopback_session_hints[_loopback_hint_key()] = (
        time.monotonic(),
        int(user_id),
        int(session_id),
    )


def _recent_loopback_session_hint() -> tuple[int, int] | None:
    row = _loopback_session_hints.get(_loopback_hint_key())
    if not row:
        return None
    seen_at, user_id, session_id = row
    if (time.monotonic() - seen_at) > _LOOPBACK_HINT_TTL_SECONDS:
        _loopback_session_hints.pop(_loopback_hint_key(), None)
        return None

    active = (
        db.session.query(ScanSession.id)
        .filter(
            ScanSession.id == session_id,
            ScanSession.user_id == user_id,
            ScanSession.status == "active",
        )
        .first()
    )
    if not active:
        _loopback_session_hints.pop(_loopback_hint_key(), None)
        return None
    return int(user_id), int(session_id)


def _session_target_matches_hosts(target_url: str | None, hosts: list[str]) -> bool:
    """If we have host hints from the line, they must fit the scan's target_url (stale Burp session_id)."""
    if not hosts:
        return True
    if not target_url:
        return False
    tu = (target_url or "").lower()
    if "burp/active" in tu:
        return True
    for h in hosts:
        if not h:
            continue
        for v in (h.lower(), h[4:] if h.startswith("www.") else f"www.{h}"):
            if v and v in tu:
                return True
    return False


def _target_url_match_clauses(hosts: list[str]):
    """Build OR( target_url ILIKE %host% ) for host + www. variants."""
    variants: list[str] = []
    for h in hosts:
        if not h:
            continue
        for v in (h, h[4:] if h.startswith("www.") else f"www.{h}"):
            if v and v not in variants:
                variants.append(v)
    return [
        func.lower(ScanSession.target_url).like(f"%{v.lower()}%") for v in variants
    ]


def _session_for_hosts(
    hosts: list[str], *, active_only: bool
) -> tuple[int, int] | None:
    if not hosts:
        return None
    clauses = _target_url_match_clauses(hosts)
    if not clauses:
        return None
    q = (
        db.session.query(ScanSession.user_id, ScanSession.id)
        .filter(ScanSession.user_id.in_(db.session.query(User.id)))
    )
    if active_only:
        q = q.filter(ScanSession.status == "active")
    rows = q.filter(or_(*clauses)).order_by(ScanSession.id.desc()).all()
    if not rows:
        return None
    if len(rows) > 1:
        current_app.logger.debug(
            "rl-events inference: multiple sessions match host; use api_token or session_id"
        )
        return None
    row = rows[0]
    if row[0] is not None:
        return int(row[0]), int(row[1])
    return None


def _infer_loopback_identity(data: dict) -> tuple[int | None, int | None]:
    """
    Map Burp loopback traffic when api_token / user_id are missing from JSON.
    Ignores stale session_id if inactive or target_url doesn't match the line's host.
    """
    hosts_early = _host_candidates_from_event(data)
    if not hosts_early:
        hinted = _recent_loopback_session_hint()
        if hinted:
            return hinted

    sid = _coerce_int(data.get("session_id"))
    if sid is not None:
        row = (
            db.session.query(
                ScanSession.user_id, ScanSession.id, ScanSession.target_url
            )
            .join(User, User.id == ScanSession.user_id)
            .filter(ScanSession.id == sid)
            .filter(ScanSession.status == "active")
            .first()
        )
        if row and row[0] is not None:
            if _session_target_matches_hosts(row[2], hosts_early):
                return int(row[0]), int(row[1])

    hosts = hosts_early
    hit = _session_for_hosts(hosts, active_only=True)
    if hit:
        return hit
    hit = _session_for_hosts(hosts, active_only=False)
    if hit:
        return hit

    # Burp default target https://burp/active — only if unambiguous (one such active row).
    burp_rows = (
        db.session.query(ScanSession.user_id, ScanSession.id)
        .join(User, User.id == ScanSession.user_id)
        .filter(ScanSession.status == "active")
        .filter(func.lower(ScanSession.target_url).like("%burp/active%"))
        .order_by(ScanSession.id.desc())
        .all()
    )
    if len(burp_rows) == 1 and burp_rows[0][0] is not None:
        return int(burp_rows[0][0]), int(burp_rows[0][1])

    active_rows = (
        db.session.query(ScanSession.user_id, ScanSession.id)
        .join(User, User.id == ScanSession.user_id)
        .filter(ScanSession.status == "active")
        .order_by(ScanSession.id.desc())
        .all()
    )
    if len(active_rows) == 1 and active_rows[0][0] is not None:
        r = active_rows[0]
        current_app.logger.debug(
            "rl-events loopback: using sole active session user_id=%s id=%s",
            r[0],
            r[1],
        )
        return int(r[0]), int(r[1])

    if len(active_rows) > 1 and active_rows[0][0] is not None:
        r = active_rows[0]
        current_app.logger.warning(
            "rl-events loopback: %d active sessions exist; using most recent "
            "user_id=%s id=%s. Set api_token or session_id in Burp to be explicit.",
            len(active_rows),
            r[0],
            r[1],
        )
        return int(r[0]), int(r[1])

    # No active sessions — fall back to the most recently created session for any user.
    any_row = (
        db.session.query(ScanSession.user_id, ScanSession.id)
        .join(User, User.id == ScanSession.user_id)
        .filter(ScanSession.user_id.isnot(None))
        .order_by(ScanSession.id.desc())
        .first()
    )
    if any_row and any_row[0] is not None:
        current_app.logger.warning(
            "rl-events loopback: no active sessions; falling back to most recent session "
            "user_id=%s id=%s. Start a scan from the dashboard to associate events properly.",
            any_row[0],
            any_row[1],
        )
        return int(any_row[0]), int(any_row[1])

    return None, None


@rl_event_bp.get("/api/rl-logs/latest-id")
def latest_rl_log_id():
    m = db.session.query(func.max(RLLog.id)).scalar()
    return jsonify({"id": int(m or 0)})


@rl_event_bp.get("/api/rl-logs/bootstrap")
def bootstrap_rl_logs():
    """Last N rows so the dashboard is not empty when poll cursor is at max id."""
    limit = min(request.args.get("limit", type=int) or 150, 500)
    sf = _active_session_filter()
    uid = _dashboard_user_scope()
    if uid is None:
        return jsonify({"error": "Authentication required"}), 401
    base = db.session.query(RLLog.id)
    base = base.filter(RLLog.user_id == uid)
    if sf is not None:
        base = base.filter(RLLog.session_id == sf)
    ids_rows = base.order_by(RLLog.id.desc()).limit(limit).all()
    id_list = sorted(r[0] for r in ids_rows)
    if not id_list:
        return jsonify({"lines": [], "max_id": 0})
    rows = (
        RLLog.query.filter(RLLog.id.in_(id_list))
        .order_by(RLLog.id.asc())
        .all()
    )
    lines = []
    for r in rows:
        xai = build_rl_xai_payload(r.raw_line, parse_structured_from_raw(r.raw_line))
        lines.append({"id": r.id, "line": r.raw_line, "xai": xai})
    return jsonify({"lines": lines, "max_id": max(id_list)})


@rl_event_bp.get("/api/rl-logs/recent")
def recent_rl_logs():
    after_id = request.args.get("after_id", type=int) or 0
    limit = min(request.args.get("limit", type=int) or 100, 500)
    sf = _active_session_filter()
    uid = _dashboard_user_scope()
    if uid is None:
        return jsonify({"error": "Authentication required"}), 401
    q = RLLog.query.filter(RLLog.id > after_id)
    q = q.filter(RLLog.user_id == uid)
    if sf is not None:
        q = q.filter(RLLog.session_id == sf)
    q = q.order_by(RLLog.id.asc()).limit(limit)
    lines = []
    for r in q.all():
        xai = build_rl_xai_payload(r.raw_line, parse_structured_from_raw(r.raw_line))
        lines.append({"id": r.id, "line": r.raw_line, "xai": xai})
    return jsonify({"lines": lines})


@rl_event_bp.get("/api/rl-event/latest-xai")
def latest_xai():
    try:
        row = RLEvent.query.order_by(RLEvent.id.desc()).first()
    except Exception as exc:
        current_app.logger.warning("latest-xai query failed: %s", exc)
        return jsonify({"explanation": None, "context": None})
    if not row:
        return jsonify({"explanation": None, "context": None})
    expl = (row.explanation or "").strip()
    ctx = {
        "event_type": row.event_type,
        "action_name": row.action_name,
        "action_id": row.action_id,
        "url": row.url,
        "http_method": row.http_method,
        "status_code": row.status_code,
        "reward": row.reward,
        "request_id": row.request_id,
    }
    if not expl and row.raw_line:
        xai = build_rl_xai_payload(row.raw_line, parse_structured_from_raw(row.raw_line))
        expl = xai["explanation"]
        ctx = {**ctx, **xai["context"]}
    return jsonify({"explanation": expl or None, "context": ctx})


@rl_event_bp.route("/api/rl-events", methods=["POST", "OPTIONS"])
def receive_rl_event():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}

    auth_uid = resolve_rl_actor_user_id(request, data)
    allow_unauthenticated = False
    allow_anon_loopback = current_app.config.get(
        "RL_ALLOW_ANON_LOOPBACK_EVENTS", True
    )
    if auth_uid is None and allow_anon_loopback and trusted_loopback(request):
        # Local-dev fallback: infer user/session from payload + DB (no log spam per request).
        allow_unauthenticated = True
        inferred_uid, inferred_sid = _infer_loopback_identity(data)
        if inferred_uid is not None:
            auth_uid = inferred_uid
            # Overwrite stale Burp session_id when inference picked a different scan.
            if inferred_sid is not None:
                data["session_id"] = inferred_sid
        else:
            return jsonify(
                {
                    "error": "Cannot map Burp event to a user/session",
                    "hint": (
                        "Set Burp preference rl_api_token to the api_token for your user in the DB, "
                        "or set burp_rl_user_id (e.g. 12). Start a scan from the dashboard so "
                        "target_url matches traffic (or use the extension default https://burp/active). "
                        "If many sessions are active, complete stale ones in the DB or rely on token/user_id."
                    ),
                }
            ), 400
    if auth_uid is None and not allow_unauthenticated:
        return jsonify(
            {
                "error": "Authentication required",
                "hint": (
                    "Set Montoya preference rl_api_token (or env BURP_RL_API_TOKEN) to your "
                    "users.api_token from the dashboard /auth/me — or for local Burp only, set "
                    "preference burp_rl_user_id (or env BURP_RL_USER_ID) to your users.id "
                    "(loopback trust; disable with RL_TRUST_LOOPBACK_USER_ID=false)."
                ),
            }
        ), 401

    body_sid = _coerce_int(data.get("session_id"))
    if body_sid is not None and auth_uid is not None:
        row = (
            db.session.query(ScanSession.user_id, ScanSession.status)
            .filter(ScanSession.id == body_sid)
            .first()
        )
        if not row:
            return jsonify({"error": "Unknown session_id"}), 404
        if int(row[0]) != int(auth_uid):
            return jsonify({"error": "Invalid session_id for this user"}), 403
        if row[1] != "active":
            data.pop("session_id", None)

    try:
        result = ingest_rl_event(data, session, auth_user_id=auth_uid)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    raw_line = result["raw_line"]
    current_app.logger.info(
        "rl-events broadcast: %s",
        (raw_line[:100] + "…") if len(raw_line) > 100 else raw_line,
    )

    room = f"user_{int(auth_uid)}"
    socketio.emit(
        "rl_log",
        {
            "line": raw_line,
            "session_id": result.get("session_id"),
            "xai": result.get("xai"),
        },
        to=room,
    )

    if trusted_loopback(request) and _host_candidates_from_event(data):
        _remember_loopback_session_hint(
            int(auth_uid),
            _coerce_int(result.get("session_id")),
        )

    return jsonify({"status": "ok"}), 200
