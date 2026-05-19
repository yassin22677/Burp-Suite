"""
Unit tests for the team profile service and routes.

All tests run fully offline — no database, no running server required.
DB calls are monkeypatched; Flask app is used via the test client.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_PROFILE = {
    "schema_version": "1.0",
    "profile_name": "Test Profile",
    "description": "For automated testing",
    "exported_at": "2026-05-12T00:00:00+00:00",
    "exported_by": "lead_tester",
    "targets": [
        {"base_url": "https://target.example.com", "environment": "test", "notes": ""},
        {"base_url": "https://prod.example.com", "environment": "prod", "notes": ""},
    ],
    "session_template": {
        "token_type": "header",
        "token_keys": ["Authorization"],
        "notes": "Bearer token",
    },
    "proxy": {
        "burp_proxy_url": "http://127.0.0.1:8080",
        "request_timeout_seconds": 30,
    },
    "scanner_policy": {
        "preset_id": "balanced_audit",
        "signals": {"prefer_fp_reduction": False, "recent_429_rate": 0.0},
    },
    "rl_settings": {"trust_loopback": True, "allow_anon_loopback": False},
    "notes": "Follow the manual steps after importing.",
}


# ---------------------------------------------------------------------------
# _validate_profile
# ---------------------------------------------------------------------------

class TestValidateProfile:
    def setup_method(self):
        from app.services.team_profile import _validate_profile
        self._validate = _validate_profile

    def test_valid_minimal(self):
        errors = self._validate({
            "schema_version": "1.0",
            "targets": [{"base_url": "https://x.test"}],
        })
        assert errors == []

    def test_valid_full_profile(self):
        assert self._validate(VALID_PROFILE) == []

    def test_wrong_type(self):
        errs = self._validate("not a dict")
        assert any("JSON object" in e for e in errs)

    def test_unsupported_schema_version(self):
        bad = {**VALID_PROFILE, "schema_version": "99.0"}
        errs = self._validate(bad)
        assert any("schema_version" in e for e in errs)

    def test_targets_not_list(self):
        bad = {**VALID_PROFILE, "targets": "should-be-list"}
        errs = self._validate(bad)
        assert any("targets" in e for e in errs)

    def test_target_missing_base_url(self):
        bad = {**VALID_PROFILE, "targets": [{"environment": "test"}]}
        errs = self._validate(bad)
        assert any("base_url" in e for e in errs)

    def test_target_empty_base_url(self):
        bad = {**VALID_PROFILE, "targets": [{"base_url": "   "}]}
        errs = self._validate(bad)
        assert any("base_url" in e for e in errs)

    def test_bad_token_type(self):
        bad = {**VALID_PROFILE,
               "session_template": {"token_type": "oauth", "token_keys": []}}
        errs = self._validate(bad)
        assert any("token_type" in e for e in errs)

    def test_cookie_token_type_valid(self):
        ok = {**VALID_PROFILE,
              "session_template": {"token_type": "cookie", "token_keys": ["session"]}}
        assert self._validate(ok) == []

    def test_invalid_scanner_preset(self):
        bad = {**VALID_PROFILE,
               "scanner_policy": {"preset_id": "nonexistent_preset"}}
        errs = self._validate(bad)
        assert any("preset_id" in e for e in errs)

    def test_proxy_not_dict(self):
        bad = {**VALID_PROFILE, "proxy": "http://127.0.0.1:8080"}
        errs = self._validate(bad)
        assert any("proxy" in e for e in errs)

    def test_empty_targets_is_valid(self):
        ok = {**VALID_PROFILE, "targets": []}
        assert self._validate(ok) == []


# ---------------------------------------------------------------------------
# preview_team_profile
# ---------------------------------------------------------------------------

class TestPreviewTeamProfile:
    def _make_conn(self, existing_urls=None):
        """Return a context-manager mock whose cursor yields existing_urls rows."""
        existing_urls = existing_urls or []
        cur = MagicMock()
        cur.fetchall.return_value = [(u,) for u in existing_urls]
        conn = MagicMock()
        conn.__enter__ = MagicMock(return_value=conn)
        conn.__exit__ = MagicMock(return_value=False)
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cur)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        return conn

    def test_invalid_profile_returns_errors(self):
        from app.services.team_profile import preview_team_profile

        result = preview_team_profile(1, {"schema_version": "bad"})
        assert result["valid"] is False
        assert result["errors"]

    def test_all_targets_new(self):
        from app.services.team_profile import preview_team_profile

        conn_mock = self._make_conn([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = preview_team_profile(1, VALID_PROFILE)

        assert result["valid"] is True
        assert len(result["new_targets"]) == 2
        assert result["existing_targets_skipped"] == []

    def test_one_existing_target_skipped(self):
        from app.services.team_profile import preview_team_profile

        conn_mock = self._make_conn(["https://target.example.com"])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = preview_team_profile(1, VALID_PROFILE)

        assert result["valid"] is True
        assert len(result["new_targets"]) == 1
        assert len(result["existing_targets_skipped"]) == 1
        assert result["existing_targets_skipped"][0]["base_url"] == "https://target.example.com"

    def test_instructions_mention_token_type(self):
        from app.services.team_profile import preview_team_profile

        conn_mock = self._make_conn([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = preview_team_profile(1, VALID_PROFILE)

        joined = " ".join(result["instructions"])
        assert "header" in joined.lower()

    def test_instructions_mention_proxy(self):
        from app.services.team_profile import preview_team_profile

        conn_mock = self._make_conn([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = preview_team_profile(1, VALID_PROFILE)

        assert any("proxy" in s.lower() or "8080" in s for s in result["instructions"])

    def test_scanner_policy_in_instructions(self):
        from app.services.team_profile import preview_team_profile

        conn_mock = self._make_conn([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = preview_team_profile(1, VALID_PROFILE)

        assert any("balanced_audit" in s for s in result["instructions"])


# ---------------------------------------------------------------------------
# apply_team_profile
# ---------------------------------------------------------------------------

class TestApplyTeamProfile:
    def _conn_mock(self, existing_urls=None):
        existing_urls = existing_urls or []
        cur = MagicMock()
        cur.fetchall.return_value = [(u,) for u in existing_urls]
        cur.fetchone.return_value = None
        conn = MagicMock()
        conn.__enter__ = MagicMock(return_value=conn)
        conn.__exit__ = MagicMock(return_value=False)
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cur)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        return conn

    def test_invalid_profile_not_applied(self):
        from app.services.team_profile import apply_team_profile

        result = apply_team_profile(1, {"schema_version": "bad"})
        assert result["applied"] is False
        assert result["errors"]

    def test_new_targets_inserted(self):
        from app.services.team_profile import apply_team_profile

        conn_mock = self._conn_mock([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = apply_team_profile(1, VALID_PROFILE)

        assert result["applied"] is True
        assert set(result["targets_added"]) == {
            "https://target.example.com",
            "https://prod.example.com",
        }
        assert result["targets_skipped"] == []

    def test_existing_targets_skipped(self):
        from app.services.team_profile import apply_team_profile

        conn_mock = self._conn_mock(["https://target.example.com"])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = apply_team_profile(1, VALID_PROFILE)

        assert result["applied"] is True
        assert "https://target.example.com" in result["targets_skipped"]
        assert "https://prod.example.com" in result["targets_added"]

    def test_auth_step_shown_when_no_active_session(self):
        from app.services.team_profile import apply_team_profile

        conn_mock = self._conn_mock([])
        # _user_has_active_session will use the same mock → fetchone returns None → no session
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = apply_team_profile(1, VALID_PROFILE)

        joined = " ".join(result["manual_steps"])
        assert "authorization" in joined.lower() or "token" in joined.lower()

    def test_auth_step_suppressed_when_session_exists(self):
        from app.services.team_profile import apply_team_profile

        conn_mock = self._conn_mock([])
        # Patch _user_has_active_session directly to return True
        with patch("app.services.team_profile.get_connection", return_value=conn_mock), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, VALID_PROFILE)

        joined = " ".join(result["manual_steps"])
        assert "token_type" not in joined and "set up a" not in joined

    def test_proxy_step_suppressed_when_already_matching(self):
        from app.services.team_profile import apply_team_profile
        import app.services.team_profile as svc

        # Profile proxy matches the server's current BURP_PROXY_URL
        profile = {**VALID_PROFILE, "proxy": {
            "burp_proxy_url": svc.BURP_PROXY_URL,
            "request_timeout_seconds": svc.REQUEST_TIMEOUT_SECONDS,
        }}
        conn_mock = self._conn_mock([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert not any("BURP_PROXY_URL" in s for s in result["manual_steps"])

    def test_proxy_step_shown_when_different(self):
        from app.services.team_profile import apply_team_profile

        profile = {**VALID_PROFILE, "proxy": {
            "burp_proxy_url": "http://10.0.0.5:9090",
            "request_timeout_seconds": 60,
        }}
        conn_mock = self._conn_mock([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert any("9090" in s or "BURP_PROXY_URL" in s for s in result["manual_steps"])

    def test_scanner_step_suppressed_for_default_preset(self):
        from app.services.team_profile import apply_team_profile

        conn_mock = self._conn_mock([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, VALID_PROFILE)  # preset_id = balanced_audit

        assert not any("scanner policy" in s.lower() for s in result["manual_steps"])

    def test_scanner_step_shown_for_non_default_preset(self):
        from app.services.team_profile import apply_team_profile

        profile = {**VALID_PROFILE, "scanner_policy": {"preset_id": "active_thorough"}}
        conn_mock = self._conn_mock([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert any("active_thorough" in s for s in result["manual_steps"])

    def test_manual_steps_empty_when_everything_already_configured(self):
        from app.services.team_profile import apply_team_profile
        import app.services.team_profile as svc

        profile = {
            **VALID_PROFILE,
            "proxy": {
                "burp_proxy_url": svc.BURP_PROXY_URL,
                "request_timeout_seconds": svc.REQUEST_TIMEOUT_SECONDS,
            },
            "scanner_policy": {"preset_id": "balanced_audit"},
            "rl_settings": {"trust_loopback": True, "allow_anon_loopback": True},
        }
        conn_mock = self._conn_mock([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert result["manual_steps"] == [], result["manual_steps"]

    def test_profile_name_preserved(self):
        from app.services.team_profile import apply_team_profile

        conn_mock = self._conn_mock([])
        with patch("app.services.team_profile.get_connection", return_value=conn_mock):
            result = apply_team_profile(1, VALID_PROFILE)

        assert result["profile_name"] == "Test Profile"
        assert result["exported_by"] == "lead_tester"


# ---------------------------------------------------------------------------
# Flask routes (test client — no real DB)
# ---------------------------------------------------------------------------

@pytest.fixture
def flask_test_client(monkeypatch):
    """
    Create the Flask app in test mode with all DB calls stubbed out so the
    test client works without a running PostgreSQL server.
    """
    import psycopg2

    # Prevent the app factory's connectivity probe from failing
    monkeypatch.setattr(
        psycopg2,
        "connect",
        lambda *a, **kw: (_ for _ in ()).throw(psycopg2.OperationalError("no db in test")),
    )

    import importlib
    import app as app_pkg

    # Reload to pick up a fresh app without cached module state
    importlib.reload(app_pkg)

    flask_app = app_pkg.create_app()
    flask_app.config["TESTING"] = True
    flask_app.config["SECRET_KEY"] = "test-secret"

    with flask_app.test_client() as client:
        yield client


class TestTeamProfileRoutes:
    def test_export_requires_auth(self, flask_test_client):
        r = flask_test_client.get("/api/team/profile/export")
        assert r.status_code == 401

    def test_preview_requires_auth(self, flask_test_client):
        r = flask_test_client.post(
            "/api/team/profile/preview",
            data=json.dumps(VALID_PROFILE),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_import_requires_auth(self, flask_test_client):
        r = flask_test_client.post(
            "/api/team/profile/import",
            data=json.dumps(VALID_PROFILE),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_preview_bad_json_returns_400(self, flask_test_client):
        with flask_test_client.session_transaction() as sess:
            sess["user_id"] = 99

        r = flask_test_client.post(
            "/api/team/profile/preview",
            data="not json{{",
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_preview_invalid_profile_returns_errors(self, flask_test_client):
        with flask_test_client.session_transaction() as sess:
            sess["user_id"] = 99

        bad = {"schema_version": "0.0", "targets": []}

        with patch("app.services.team_profile.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchall.return_value = []
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn.return_value)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            mock_conn.return_value.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
            mock_conn.return_value.cursor.return_value.__exit__ = MagicMock(return_value=False)

            r = flask_test_client.post(
                "/api/team/profile/preview",
                data=json.dumps(bad),
                content_type="application/json",
            )

        assert r.status_code == 200
        data = r.get_json()
        assert data["valid"] is False
        assert data["errors"]

    def test_preview_valid_profile_authenticated(self, flask_test_client):
        with flask_test_client.session_transaction() as sess:
            sess["user_id"] = 99

        with patch("app.services.team_profile.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchall.return_value = []
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn.return_value)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            mock_conn.return_value.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
            mock_conn.return_value.cursor.return_value.__exit__ = MagicMock(return_value=False)

            r = flask_test_client.post(
                "/api/team/profile/preview",
                data=json.dumps(VALID_PROFILE),
                content_type="application/json",
            )

        assert r.status_code == 200
        data = r.get_json()
        assert data["valid"] is True
        assert len(data["new_targets"]) == 2

    def test_import_valid_profile_authenticated(self, flask_test_client):
        with flask_test_client.session_transaction() as sess:
            sess["user_id"] = 99

        with patch("app.services.team_profile.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchall.return_value = []
            mock_cur.fetchone.return_value = None
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn.return_value)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            mock_conn.return_value.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
            mock_conn.return_value.cursor.return_value.__exit__ = MagicMock(return_value=False)

            r = flask_test_client.post(
                "/api/team/profile/import",
                data=json.dumps(VALID_PROFILE),
                content_type="application/json",
            )

        assert r.status_code == 200
        data = r.get_json()
        assert data["applied"] is True
        assert "https://target.example.com" in data["targets_added"]
        assert "https://prod.example.com" in data["targets_added"]

    def test_export_content_disposition(self, flask_test_client):
        with flask_test_client.session_transaction() as sess:
            sess["user_id"] = 99

        with patch("app.services.team_profile.get_connection") as mock_conn, \
             patch("app.services.team_profile._get_username", return_value="lead"), \
             patch("app.services.team_profile._get_user_targets", return_value=[]), \
             patch("app.services.team_profile._get_session_template", return_value={
                 "token_type": "header", "token_keys": [], "notes": ""
             }):
            r = flask_test_client.get("/api/team/profile/export")

        assert r.status_code == 200
        assert "attachment" in r.headers.get("Content-Disposition", "")
        body = r.get_json()
        assert body["schema_version"] == "1.0"

    def test_multipart_file_upload_preview(self, flask_test_client):
        """Preview endpoint also accepts multipart file uploads."""
        from io import BytesIO

        with flask_test_client.session_transaction() as sess:
            sess["user_id"] = 99

        file_data = json.dumps(VALID_PROFILE).encode()

        with patch("app.services.team_profile.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchall.return_value = []
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn.return_value)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            mock_conn.return_value.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
            mock_conn.return_value.cursor.return_value.__exit__ = MagicMock(return_value=False)

            r = flask_test_client.post(
                "/api/team/profile/preview",
                data={"profile": (BytesIO(file_data), "profile.json")},
                content_type="multipart/form-data",
            )

        assert r.status_code == 200
        data = r.get_json()
        assert data["valid"] is True
