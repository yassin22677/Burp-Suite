"""Reusable outbound HTTP wrapper with session auth and Burp proxy."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from app.services.postgres import get_connection
from app.services.proxy_config import REQUEST_PROXIES, REQUEST_TIMEOUT_SECONDS
from app.services.session_manager import (
    fetch_session_row,
    get_session_auth,
    mark_session_expired,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def _resolve_base_url(user_id: int, target_url: str) -> str:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT base_url
                FROM websites
                WHERE user_id = %s AND base_url = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (user_id, target_url),
            )
            row = cur.fetchone()
            if row and row[0]:
                return str(row[0]).strip()

    session_row = fetch_session_row(user_id=user_id, target_url=target_url)
    if session_row and session_row.get("target_url"):
        return str(session_row["target_url"]).strip()

    return target_url.strip()


def _build_full_url(base_url: str, endpoint: str) -> str:
    endpoint = endpoint or ""
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    base = base_url.rstrip("/") + "/"
    rel = endpoint.lstrip("/")
    return urljoin(base, rel)


def _token_to_headers_or_cookies(
    session_auth: dict[str, Any] | None,
) -> tuple[dict[str, str], dict[str, str]]:
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    if not session_auth:
        return headers, cookies

    token_type = session_auth.get("type")
    token_value = session_auth.get("value") or {}

    if token_type == "cookie":
        for k, v in token_value.items():
            cookies[str(k)] = str(v)
    elif token_type == "header":
        if "Authorization" in token_value:
            headers["Authorization"] = str(token_value["Authorization"])
        elif "token" in token_value:
            scheme = str(token_value.get("scheme", "Bearer"))
            headers["Authorization"] = f"{scheme} {token_value['token']}"
        else:
            for k, v in token_value.items():
                headers[str(k)] = str(v)

    return headers, cookies


def _store_http_request_log(
    *,
    user_id: int,
    session_id: int | None,
    full_url: str,
    request_headers: dict[str, Any],
    method: str,
    response_status: int,
    response_body: str,
) -> None:
    host = (urlparse(full_url).hostname or "").lower() or None
    headers_obj = dict(request_headers)
    payload = {
        "method": method.upper(),
        "url": full_url,
        "headers": headers_obj,
        "request_headers": headers_obj,
        "status": response_status,
        "response_status": response_status,
        "response": response_body,
        "response_body": response_body,
    }

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO rl_logs (user_id, session_id, target_host, event_type, raw_line)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        session_id,
                        host,
                        "http_request",
                        json.dumps(payload, ensure_ascii=True),
                    ),
                )
    except Exception as exc:
        logger.exception(
            "rl_logs http_request insert failed user_id=%s session_id=%s: %s",
            user_id,
            session_id,
            exc,
        )
        raise


def send_request(
    user_id: int,
    target_url: str,
    method: str,
    endpoint: str,
    data: Any = None,
):
    """
    Fetch session auth, inject token, route via Burp proxy, and log to rl_logs.
    """
    logger.info(
        "send_request user_id=%s target_url=%s method=%s endpoint=%s",
        user_id,
        target_url,
        method,
        endpoint,
    )
    base_url = _resolve_base_url(user_id=user_id, target_url=target_url)
    full_url = _build_full_url(base_url=base_url, endpoint=endpoint)

    session_row = fetch_session_row(user_id=user_id, target_url=target_url)
    session_auth = get_session_auth(user_id=user_id, target_url=target_url)

    auth_headers, auth_cookies = _token_to_headers_or_cookies(session_auth)

    req_kwargs: dict[str, Any] = {
        "method": method.upper(),
        "url": full_url,
        "headers": auth_headers or None,
        "cookies": auth_cookies or None,
        "proxies": REQUEST_PROXIES,
        "verify": False,
        "timeout": REQUEST_TIMEOUT_SECONDS,
    }

    if data is not None:
        if isinstance(data, (dict, list)):
            req_kwargs["json"] = data
        else:
            req_kwargs["data"] = data

    response = requests.request(**req_kwargs)

    _store_http_request_log(
        user_id=user_id,
        session_id=(session_row or {}).get("id"),
        full_url=full_url,
        request_headers=(response.request.headers if response.request else {}),
        method=method,
        response_status=response.status_code,
        response_body=response.text,
    )

    if response.status_code == 401 and session_row and session_row.get("id"):
        mark_session_expired(int(session_row["id"]))

    return response
