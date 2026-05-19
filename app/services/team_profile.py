"""
Team profile service — export, preview, and import a pentester's config bundle.

A *team profile* is a portable JSON snapshot that a lead pentester creates from
their current configuration (target websites, session token schema, proxy
settings, scanner policy preset, and RL behaviour flags) so that junior team
members can import it and start with the same baseline.

Security notice
---------------
Actual credential *values* (``token_value`` column) are **never** included in
an export.  The ``session_template`` section only records the token *type* and
key *names* (e.g. ``["Authorization"]``) so that importers know which header or
cookie field to populate themselves.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import psycopg2

from app.services.postgres import get_connection

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
SUPPORTED_VERSIONS = {"1.0"}
VALID_TOKEN_TYPES = {"cookie", "header"}
VALID_PRESET_IDS = {
    "passive_conservative",
    "balanced_audit",
    "active_thorough",
    "fp_reduction_strict",
    "throttle_passive",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_username(user_id: int) -> str:
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
                return str(row[0]) if row else f"user_{user_id}"
    except Exception:
        return f"user_{user_id}"


def _get_user_targets(user_id: int) -> list[dict[str, Any]]:
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT base_url, environment
                    FROM websites
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    """,
                    (user_id,),
                )
                return [
                    {
                        "base_url": row[0],
                        "environment": row[1] or "prod",
                        "notes": "",
                    }
                    for row in cur.fetchall()
                ]
    except Exception as exc:
        logger.warning("Failed to fetch targets for user_id=%s: %s", user_id, exc)
        return []


def _get_session_template(user_id: int) -> dict[str, Any]:
    """Return token schema from the most recent active session — no credential values."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT token_type, token_value
                    FROM sessions
                    WHERE user_id = %s AND status = 'active'
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
    except Exception as exc:
        logger.warning("Session template fetch failed user_id=%s: %s", user_id, exc)
        row = None

    if row is None:
        return {
            "token_type": "header",
            "token_keys": ["Authorization"],
            "notes": "Configure your auth token before starting a scan session.",
        }

    token_type = row[0] or "header"
    token_value = row[1] or {}
    if isinstance(token_value, str):
        try:
            token_value = json.loads(token_value)
        except Exception:
            token_value = {}

    keys = sorted(token_value.keys()) if isinstance(token_value, dict) else []
    return {
        "token_type": token_type,
        "token_keys": keys,
        "notes": (
            f"Supply your own {token_type} credentials for the key(s) listed in "
            "'token_keys'. Actual values are never exported."
        ),
    }


def _get_rl_brain_snapshot() -> dict:
    """Return the current global Q-agent's learned state, or an empty stub."""
    try:
        from app.services.rl_agent import agent  # noqa: PLC0415
        return agent.dump()
    except Exception as exc:
        logger.warning("Could not snapshot RL agent: %s", exc)
        return {"states_seen": 0, "q_table": {}, "notes": "Agent snapshot unavailable."}


def _apply_rl_brain_snapshot(snapshot: dict) -> str:
    """
    Load a Q-table snapshot into the global agent.
    Returns a human-readable status string.
    """
    if not snapshot or not isinstance(snapshot, dict):
        return "No brain snapshot in profile — skipped."
    if not snapshot.get("q_table"):
        return "Brain snapshot is empty (lead had 0 states trained) — skipped."
    try:
        from app.services.rl_agent import agent  # noqa: PLC0415
        agent.load(snapshot)
        return (
            f"Loaded {snapshot.get('states_seen', '?')} trained state(s) from lead's Q-table. "
            f"Epsilon carried over: {snapshot.get('epsilon', '?')}."
        )
    except Exception as exc:
        logger.warning("RL brain import failed: %s", exc)
        return f"Brain snapshot could not be loaded: {exc}"


def _user_has_active_session(user_id: int) -> bool:
    """Return True if the user already has at least one active scan session with a token."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id FROM sessions
                    WHERE user_id = %s AND status = 'active'
                      AND token_type IS NOT NULL AND token_value IS NOT NULL
                    LIMIT 1
                    """,
                    (user_id,),
                )
                return cur.fetchone() is not None
    except Exception:
        return False


def _existing_urls(user_id: int) -> set[str]:
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT LOWER(base_url) FROM websites WHERE user_id = %s",
                    (user_id,),
                )
                return {row[0] for row in cur.fetchall()}
    except Exception:
        return set()


def _insert_website(user_id: int, base_url: str, environment: str) -> None:
    """Insert a website row, skipping if the URL already exists for this user."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM websites
                WHERE user_id = %s AND LOWER(base_url) = LOWER(%s)
                LIMIT 1
                """,
                (user_id, base_url),
            )
            if cur.fetchone():
                return
            cur.execute(
                """
                INSERT INTO websites (user_id, base_url, environment)
                VALUES (%s, %s, %s)
                """,
                (user_id, base_url, environment or "prod"),
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_team_profile(
    user_id: int,
    *,
    profile_name: str = "",
    description: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Build a portable team profile snapshot from the current user's setup."""
    username = _get_username(user_id)

    try:
        from flask import current_app  # noqa: PLC0415

        rl_trust = bool(current_app.config.get("RL_TRUST_LOOPBACK_USER_ID", True))
        rl_anon = bool(current_app.config.get("RL_ALLOW_ANON_LOOPBACK_EVENTS", True))
    except RuntimeError:
        rl_trust = True
        rl_anon = True

    return {
        "schema_version": SCHEMA_VERSION,
        "profile_name": profile_name.strip() or f"{username}'s team profile",
        "description": description.strip(),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": username,
        # ---- target websites ----
        "targets": _get_user_targets(user_id),
        # ---- session auth schema (no credential values) ----
        "session_template": _get_session_template(user_id),
        # ---- scanner policy ----
        "scanner_policy": {
            "preset_id": "balanced_audit",
            "available_presets": sorted(VALID_PRESET_IDS),
            "signals": {
                "prefer_fp_reduction": False,
                "recent_429_rate": 0.0,
                "suggest_active_deep_scan": False,
            },
            "notes": (
                "Change preset_id to one of the values in 'available_presets'. "
                "Update your ExperimentRunnerConfig.scanner_policy_selector "
                "or HeuristicScannerPolicySelector signals to match."
            ),
        },
        # ---- RL behaviour flags ----
        "rl_settings": {
            "trust_loopback": rl_trust,
            "allow_anon_loopback": rl_anon,
            "notes": (
                "Apply by setting env vars RL_TRUST_LOOPBACK_USER_ID and "
                "RL_ALLOW_ANON_LOOPBACK_EVENTS, then restarting. "
                "Set both to false in production."
            ),
        },
        # ---- RL agent brain snapshot (Q-table) ----
        "rl_brain": _get_rl_brain_snapshot(),
        # ---- freeform lead instructions ----
        "notes": notes.strip(),
    }


def _validate_profile(data: Any) -> list[str]:
    """Return validation error strings; empty list means valid."""
    if not isinstance(data, dict):
        return ["Profile must be a JSON object."]

    errors: list[str] = []

    version = data.get("schema_version")
    if version not in SUPPORTED_VERSIONS:
        errors.append(
            f"Unsupported schema_version: {version!r}. "
            f"Supported: {sorted(SUPPORTED_VERSIONS)}."
        )

    targets = data.get("targets", [])
    if not isinstance(targets, list):
        errors.append("'targets' must be a JSON array.")
    else:
        for i, t in enumerate(targets):
            if not isinstance(t, dict):
                errors.append(f"targets[{i}] must be a JSON object.")
            elif not isinstance(t.get("base_url"), str) or not t["base_url"].strip():
                errors.append(
                    f"targets[{i}].base_url is required and must be a non-empty string."
                )

    tmpl = data.get("session_template")
    if tmpl is not None:
        if not isinstance(tmpl, dict):
            errors.append("'session_template' must be a JSON object.")
        elif tmpl.get("token_type") not in (None, *VALID_TOKEN_TYPES):
            errors.append(
                f"session_template.token_type must be one of {sorted(VALID_TOKEN_TYPES)}."
            )

    proxy = data.get("proxy")
    if proxy is not None and not isinstance(proxy, dict):
        errors.append("'proxy' must be a JSON object.")

    scanner = data.get("scanner_policy")
    if scanner is not None:
        if not isinstance(scanner, dict):
            errors.append("'scanner_policy' must be a JSON object.")
        elif scanner.get("preset_id") not in (None, *VALID_PRESET_IDS):
            errors.append(
                f"scanner_policy.preset_id must be one of {sorted(VALID_PRESET_IDS)}."
            )

    return errors


def preview_team_profile(user_id: int, data: Any) -> dict[str, Any]:
    """Return a diff/summary of what an import would change — no writes."""
    errors = _validate_profile(data)
    if errors:
        return {"valid": False, "errors": errors}

    existing = _existing_urls(user_id)
    incoming = data.get("targets", [])

    new_targets = [
        t for t in incoming
        if isinstance(t, dict)
        and t.get("base_url", "").strip().lower() not in existing
    ]
    skipped_targets = [
        t for t in incoming
        if isinstance(t, dict)
        and t.get("base_url", "").strip().lower() in existing
    ]

    proxy = data.get("proxy") or {}
    scanner = data.get("scanner_policy") or {}
    session_template = data.get("session_template") or {}
    rl_settings = data.get("rl_settings") or {}

    return {
        "valid": True,
        "profile_name": data.get("profile_name", ""),
        "description": data.get("description", ""),
        "exported_by": data.get("exported_by", ""),
        "exported_at": data.get("exported_at", ""),
        "new_targets": new_targets,
        "existing_targets_skipped": skipped_targets,
        "notes": data.get("notes", ""),
    }


def apply_team_profile(user_id: int, data: Any) -> dict[str, Any]:
    """
    Apply a team profile to *user_id*:

    * Creates ``websites`` rows for every new target URL.
    * Returns structured instructions for steps that require env-var or
      manual changes (tokens, proxy, scanner preset, RL flags).
    """
    preview = preview_team_profile(user_id, data)
    if not preview["valid"]:
        return {"applied": False, "errors": preview.get("errors", [])}

    added: list[str] = []
    skipped: list[str] = [t["base_url"] for t in preview["existing_targets_skipped"]]
    failed: list[str] = []

    for t in preview["new_targets"]:
        base_url = t.get("base_url", "").strip()
        environment = (t.get("environment") or "prod").strip()
        if not base_url:
            continue
        try:
            _insert_website(user_id, base_url, environment)
            added.append(base_url)
            logger.info(
                "team_profile import: added website user_id=%s url=%s env=%s",
                user_id,
                base_url,
                environment,
            )
        except psycopg2.Error as exc:
            logger.warning(
                "team_profile import: website insert failed user_id=%s url=%s: %s",
                user_id,
                base_url,
                exc,
            )
            failed.append(base_url)

    brain_status = _apply_rl_brain_snapshot(data.get("rl_brain") or {})

    return {
        "applied": True,
        "profile_name": data.get("profile_name", ""),
        "description": data.get("description", ""),
        "exported_by": data.get("exported_by", ""),
        "targets_added": added,
        "targets_skipped": skipped,
        "targets_failed": failed,
        "rl_brain_status": brain_status,
        "notes": data.get("notes", ""),
    }
