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


def _parse_error(raw_line: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m = re.search(r"\[RL\]\[ERROR\]\s*(.*)$", raw_line or "", re.DOTALL)
    if m:
        out["error_message"] = m.group(1).strip()[:4000]
    return out


_APPLY_PLAIN: dict[str, str] = {
    "PASSIVE_SCAN": (
        "What this means: Burp watches traffic and runs passive checks—it does not "
        "aggressively attack the site from this setting alone."
    ),
    "ACTIVE_SCAN": (
        "What this means: Burp actively probes for vulnerabilities (more intrusive than passive only)."
    ),
    "NO_OP": (
        "What this means: the assistant did not change Burp configuration on this step; it kept the current setup."
    ),
    "DISABLE_INTERCEPT": (
        "What this means: Proxy Intercept is turned off. Requests and responses are not held in the "
        "Intercept tab for manual review—they pass through automatically. The assistant usually does this "
        "so automated crawling and RL traffic are not stuck waiting for you to click Forward."
    ),
    "ENABLE_INTERCEPT": (
        "What this means: Proxy Intercept is turned on. Traffic that matches your intercept rules can pause "
        "until you forward or drop it. That gives manual control but can slow or block a fully automated "
        "run if messages pile up in the Intercept queue."
    ),
}


def _lines_score_not_on_this_step() -> list[str]:
    """REQ / ACT / APPLY: user expects a number—explain where it will show up."""
    return [
        "When a reward or penalty appears (not on this line)",
        "This line has no score. Rewards and penalties are numbers that show up after the environment "
        "judges an outcome—almost always on a later [RL][RESP] line as reward=… and/or on a "
        "[RL][REWARD] line as value=…. "
        "Positive = reward, negative = penalty, zero = neutral. "
        "Follow the log downward from here to find the next RESP or REWARD line for this traffic.",
    ]


def _score_explanation_lines(reward: int | None) -> list[str]:
    """User-facing paragraphs: what the number is, and why it is a reward, penalty, or neutral."""
    if reward is None:
        return [
            "No score on this line",
            "This line usually does not carry a reward number. Scores typically appear on "
            "[RL][RESP] or [RL][REWARD] lines after the server (or your training code) reacts to what happened.",
        ]
    if reward > 0:
        return [
            f"The score on this line: +{reward} (this is a reward)",
            "Why you see a reward (positive number)",
            "A positive score means the RL setup judged this outcome as good for the goal "
            "(for example: a successful HTTP response, discovering a new URL or behavior, "
            "scanner progress, or a rule in your reward code that adds points for this situation). "
            "The assistant is encouraged to make similar choices when it sees a similar situation again.",
            "This is not a random number—it is how the system says “that last move helped.”",
        ]
    if reward < 0:
        return [
            f"The score on this line: {reward} (this is a penalty)",
            "Why you see a penalty (negative number)",
            "A negative score means the RL setup judged this outcome as bad or wasteful. "
            "Typical reasons include: HTTP errors (4xx/5xx), blocked or failed requests, "
            "timeouts, repeating useless steps, or a rule in your reward code that subtracts points.",
            "The assistant is nudged to try something different next time instead of repeating the same pattern.",
            "Compare to a reward: a positive score would mean the opposite—the step was considered useful.",
        ]
    return [
        "The score on this line: 0 (neutral)",
        "Why the score is zero",
        "Zero means neither a clear win nor a clear loss. The step was recorded, but the training signal "
        "does not strongly say “do more of this” or “avoid this.” The next action still depends on the "
        "overall policy and other recent rewards and penalties.",
    ]


def _http_status_plain(status_code: int | None) -> str | None:
    if status_code is None:
        return None
    sc = int(status_code)
    if 200 <= sc < 300:
        return "Success range: the server accepted the request and returned a normal response."
    if 300 <= sc < 400:
        return "Redirect: the client may follow a new location; the assistant may treat this as progress or noise depending on your rules."
    if 400 <= sc < 500:
        return "Client error: often “not found” or “bad request”—usually worse for reward unless your rules reward probing errors."
    if 500 <= sc < 600:
        return "Server error: the application failed processing—often leads to penalties if your reward code punishes errors."
    return "Unusual status; check the response body and your reward rules for how this is scored."


def build_rl_xai_payload(
    raw_line: str, merged: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Human-readable explanation for dashboard XAI (from log structure only).
    Returns {explanation, context} for API/WebSocket/UI.
    """
    m = dict(merged) if merged else parse_structured_from_raw(raw_line)
    et = (m.get("event_type") or infer_event_type(raw_line) or "UNKNOWN").upper()
    ctx: dict[str, Any] = {
        "event_type": et,
        "action_name": m.get("action_name"),
        "action_id": m.get("action_id"),
        "url": m.get("url"),
        "http_method": m.get("http_method"),
        "status_code": m.get("status_code"),
        "reward": m.get("reward"),
        "request_id": m.get("request_id"),
    }

    lines: list[str] = []

    if et == "REQ":
        method = m.get("http_method") or "HTTP"
        url = m.get("url") or "(URL not parsed from line)"
        rid = m.get("request_id")
        lines.append("What happened")
        lines.append(
            f"The assistant sent {method} {url} through Burp so the application responds and the RL loop can observe the result."
        )
        lines.append("Why this request was made")
        lines.append(
            "The assistant explores the target by sending real traffic. Each response updates what it “sees” "
            "and feeds the next decision (which Burp mode to use, what to scan, etc.). "
            "It is not a human clicking; it follows the current policy and training."
        )
        if rid is not None:
            lines.append(
                f"Technical note: request id {rid} ties this line to matching ACT / APPLY / RESP lines in the same step."
            )
        lines.extend(_lines_score_not_on_this_step())

    elif et == "ACT":
        aid = m.get("action_id")
        an = m.get("action_name") or (
            f"RL_VALUE_{aid}" if aid is not None else "unknown discrete action"
        )
        lines.append("What happened")
        lines.append(
            f"The assistant chose option “{an}” (internal index {aid if aid is not None else '—'}). "
            "That number is a code: your integration maps it to a concrete Burp action on the next APPLY line."
        )
        lines.append("Why this action was taken (what you should tell a user)")
        lines.append(
            "The log does not contain a sentence like “because the login page looked interesting.” "
            "Instead, the model picks the code that currently scores best given everything it has observed "
            "(URLs, responses, rewards, and penalties from earlier steps) and how it was trained or fine-tuned."
        )
        lines.append(
            "So: this action was taken because the RL policy at this moment preferred this option over the other "
            "numbered options—not because someone manually selected it in the UI."
        )
        lines.extend(_lines_score_not_on_this_step())

    elif et == "APPLY":
        an = (m.get("action_name") or "CONFIG_CHANGE").strip() or "CONFIG_CHANGE"
        url = m.get("url")
        host = m.get("target_host")
        lines.append("What happened")
        lines.append(
            f"The assistant actually changed Burp behavior: “{an}”. This is the visible effect of the last ACT choice."
        )
        plain = _APPLY_PLAIN.get(an.upper())
        if plain:
            lines.append(plain)
        lines.append("Why this matters")
        lines.append(
            "Rewards and penalties you see later are partly based on whether this setting helped testing "
            "(coverage, findings, stable traffic) or caused problems (errors, noise, wasted steps)—according to your reward rules."
        )
        if url:
            lines.append(f"Related URL in the log: {url}.")
        elif host:
            lines.append(f"Target host in the log: {host}.")
        lines.extend(_lines_score_not_on_this_step())

    elif et == "RESP":
        sc = m.get("status_code")
        rw = m.get("reward")
        lines.append("What happened")
        if sc is not None:
            lines.append(f"The server answered with HTTP status {sc}.")
            hint = _http_status_plain(sc)
            if hint:
                lines.append(hint)
        else:
            lines.append("A response was logged, but the status code was not parsed from this line.")
        if rw is not None:
            lines.append("When reward or penalty appears")
            lines.append(
                "On this [RL][RESP] line: look at reward=…. "
                "A positive value is a reward, a negative value is a penalty, zero is neutral."
            )
        else:
            lines.append("When reward or penalty appears")
            lines.append(
                "This line has no reward= field after parsing. The score may be emitted on the next "
                "[RL][REWARD] line (value=…) or omitted if your pipeline does not attach a number to this response."
            )
        lines.extend(_score_explanation_lines(rw))
        if sc is not None and rw is not None:
            lines.append("How status and score fit together")
            lines.append(
                "The status code describes the server’s answer. The reward/penalty number describes how your RL "
                "training setup judged that answer (and possibly other signals). They are related but not the same: "
                "you can configure rewards so that even some 4xx responses are useful, or so that 200 responses are neutral."
            )

    elif et == "REWARD":
        rw = m.get("reward")
        lines.append("What happened")
        lines.append(
            "This line is a dedicated reward signal from your pipeline (extra shaping on top of raw HTTP)."
        )
        lines.append("When reward or penalty appears")
        lines.append(
            "Right here: [RL][REWARD] uses value=…. "
            "That single number is the score—positive = reward, negative = penalty, zero = neutral—"
            "for whatever your reward code decided to grade on this step."
        )
        lines.extend(_score_explanation_lines(rw))

    elif et == "SCAN":
        an = m.get("action_name") or "scanner finding"
        url = m.get("url")
        lines.append("What happened")
        lines.append(f"Scanner / analysis feedback: {an}.")
        lines.append("Why this affects rewards")
        lines.append(
            "Many setups give a reward when new issues or interesting findings appear, because that indicates "
            "progress for security testing. If nothing new is found, the same step might earn less or no reward—"
            "depending on how your reward function is written."
        )
        if url:
            lines.append(f"Related URL: {url}.")
        lines.append("When reward or penalty appears")
        lines.append(
            "SCAN lines describe findings; they usually do not carry value= or reward= themselves. "
            "The numeric reward or penalty for the step typically appears on a nearby [RL][RESP] or [RL][REWARD] line."
        )

    elif et == "ERROR":
        msg = m.get("error_message") or raw_line
        lines.append("What happened")
        lines.append("Something failed in the RL or Burp integration; this step did not complete normally.")
        lines.append(f"Detail: {msg}")

    else:
        lines.append("What happened")
        lines.append(
            f"Event type “{et}”. Only part of the line could be interpreted automatically; read the raw line for full detail."
        )
        if m.get("reward") is not None:
            lines.extend(_score_explanation_lines(m.get("reward")))

    explanation = "\n\n".join(lines)
    return {"explanation": explanation, "context": ctx}


def _merge_user_and_auto_explanation(
    user_text: str | None, auto: str
) -> str:
    u = (user_text or "").strip()
    if not u:
        return auto
    return f"{u}\n\n— Interpretation —\n{auto}"


def parse_structured_from_raw(raw_line: str) -> dict[str, Any]:
    et = infer_event_type(raw_line) or ""
    parsers = {
        "REQ": _parse_req,
        "ACT": _parse_act,
        "APPLY": _parse_apply,
        "RESP": _parse_resp,
        "SCAN": _parse_scan,
        "REWARD": _parse_reward,
        "ERROR": _parse_error,
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

    xai = build_rl_xai_payload(raw_line, merged)
    explanation_final = _merge_user_and_auto_explanation(
        merged.get("explanation"), xai["explanation"]
    )

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
        explanation=explanation_final,
        raw_line=raw_line,
    )
    try:
        db.session.add(evt)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("rl_event insert skipped (schema mismatch OK): %s", exc)

    out_sid = str(session_fk) if session_fk is not None else None
    return {
        "raw_line": raw_line,
        "session_id": out_sid,
        "xai": {"explanation": explanation_final, "context": xai["context"]},
    }
