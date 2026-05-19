"""
Team profile export / import / preview routes.

Endpoints
---------
GET  /api/team/profile/export
    Build a team profile snapshot for the logged-in user and return it as a
    downloadable JSON file.  Optional query params: name, description, notes.

POST /api/team/profile/preview
    Accept a profile JSON (body or file upload) and return a diff summary of
    what an import would change — no writes performed.

POST /api/team/profile/import
    Accept a profile JSON (body or file upload), apply it, and return a
    structured result with what was done and what still needs manual steps.

Authentication
--------------
All endpoints require a valid Flask session cookie (POST /auth/login).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, make_response, request, session

from app.services.team_profile import (
    apply_team_profile,
    build_team_profile,
    preview_team_profile,
)

team_profile_bp = Blueprint("team_profile", __name__, url_prefix="/api/team/profile")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_session_auth() -> tuple[int | None, tuple | None]:
    """Return (user_id, None) or (None, error_response_tuple)."""
    uid = session.get("user_id")
    if not uid:
        return None, (jsonify({"error": "Authentication required"}), 401)
    try:
        return int(uid), None
    except (TypeError, ValueError):
        return None, (jsonify({"error": "Invalid session"}), 401)


def _parse_profile_body() -> tuple[dict | None, tuple | None]:
    """
    Parse the incoming profile from either a JSON body or a ``multipart/form-data``
    file upload (field name ``profile``).
    Returns (data_dict, None) on success or (None, error_response_tuple) on failure.
    """
    ct = request.content_type or ""
    if "multipart" in ct:
        f = request.files.get("profile")
        if f is None:
            return None, (jsonify({"error": "No 'profile' file field in upload"}), 400)
        try:
            data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return None, (jsonify({"error": f"Invalid JSON in uploaded file: {exc}"}), 400)
    else:
        data = request.get_json(silent=True)
        if data is None:
            return None, (jsonify({"error": "Request body must be valid JSON"}), 400)

    if not isinstance(data, dict):
        return None, (jsonify({"error": "Profile must be a JSON object"}), 400)

    return data, None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@team_profile_bp.get("/export")
def export_profile():
    """
    Build and download the current user's team profile as a JSON file.

    Query parameters (all optional):
    - ``name``        Profile name override.
    - ``description`` Short profile description.
    - ``notes``       Freeform instructions for junior testers.
    """
    uid, err = _require_session_auth()
    if err:
        return err

    profile_name = (request.args.get("name") or "").strip()
    description = (request.args.get("description") or "").strip()
    notes = (request.args.get("notes") or "").strip()

    try:
        profile = build_team_profile(
            uid,
            profile_name=profile_name,
            description=description,
            notes=notes,
        )
    except Exception as exc:
        logger.exception("team_profile export failed user_id=%s: %s", uid, exc)
        return jsonify({"error": "Failed to build team profile. Check server logs."}), 500

    payload = json.dumps(profile, indent=2, ensure_ascii=False)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"burp_team_profile_{ts}.json"

    resp = make_response(payload)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@team_profile_bp.post("/preview")
def preview_profile():
    """
    Preview what importing a profile would change — no writes performed.

    Accepts either:
    - A raw JSON body (``Content-Type: application/json``)
    - A ``multipart/form-data`` upload with a ``profile`` file field
    """
    uid, err = _require_session_auth()
    if err:
        return err

    data, parse_err = _parse_profile_body()
    if parse_err:
        return parse_err

    try:
        result = preview_team_profile(uid, data)
    except Exception as exc:
        logger.exception("team_profile preview failed user_id=%s: %s", uid, exc)
        return jsonify({"error": "Preview failed. Check server logs."}), 500

    return jsonify(result)


@team_profile_bp.post("/import")
def import_profile():
    """
    Apply a team profile to the current user's account.

    What this does automatically:
    - Creates ``websites`` rows for every new target URL in the profile.

    What requires manual steps (returned in ``manual_steps``):
    - Configuring session auth tokens (credential values are never exported).
    - Setting proxy env vars (BURP_PROXY_URL, HTTP_REQUEST_TIMEOUT).
    - Applying scanner policy preset in ExperimentRunnerConfig.
    - Setting RL env vars (RL_TRUST_LOOPBACK_USER_ID, etc.).

    Accepts either:
    - A raw JSON body (``Content-Type: application/json``)
    - A ``multipart/form-data`` upload with a ``profile`` file field
    """
    uid, err = _require_session_auth()
    if err:
        return err

    data, parse_err = _parse_profile_body()
    if parse_err:
        return parse_err

    try:
        result = apply_team_profile(uid, data)
    except Exception as exc:
        logger.exception("team_profile import failed user_id=%s: %s", uid, exc)
        return jsonify({"error": "Import failed. Check server logs."}), 500

    status_code = 200 if result.get("applied") else 400
    return jsonify(result), status_code
