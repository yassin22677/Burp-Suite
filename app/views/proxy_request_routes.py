from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.api_auth import resolve_scan_actor_user_id
from app.services.http_request_service import send_request

proxy_request_bp = Blueprint("proxy_request_bp", __name__, url_prefix="/api/proxy")


@proxy_request_bp.post("/send")
def proxy_send():
    data = request.get_json(silent=True) or {}
    user_id = resolve_scan_actor_user_id(request, data)
    if user_id is None:
        return jsonify({"error": "Authentication required"}), 401

    try:
        user_id_int = int(user_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid user_id"}), 400

    target_url = data.get("target_url")
    method = data.get("method")
    endpoint = data.get("endpoint")
    payload = data.get("data")

    if not target_url or not method or endpoint is None:
        return (
            jsonify(
                {
                    "error": "Missing required fields: target_url, method, endpoint",
                }
            ),
            400,
        )

    try:
        resp = send_request(
            user_id=user_id_int,
            target_url=str(target_url),
            method=str(method),
            endpoint=str(endpoint),
            data=payload,
        )
    except Exception as exc:
        return jsonify({"error": f"proxy request failed: {exc}"}), 502

    return (
        jsonify(
            {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
                "url": resp.url,
            }
        ),
        200,
    )
