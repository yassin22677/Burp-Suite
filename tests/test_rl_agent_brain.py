"""
Tests for QLearningAgent.dump() / .load() and the team-profile brain transfer.

Covers:
- dump() produces valid JSON-serialisable output
- load() restores Q-values exactly
- Round-trip: dump → JSON → load → same decisions
- load() is forward-compatible (unknown actions ignored, missing actions default to 0)
- Empty / untrained agent behaviour
- Brain transfer via apply_team_profile injects values into the global agent
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# QLearningAgent unit tests
# ---------------------------------------------------------------------------

class TestAgentDump:
    def _fresh_agent(self):
        from app.services.rl_agent import QLearningAgent
        return QLearningAgent()

    def test_dump_is_json_serialisable(self):
        agent = self._fresh_agent()
        # Train on one state so q_table is non-empty
        state = (0, 0, 0, 0, 0)
        agent._ensure_state(state)
        snapshot = agent.dump()
        # Must not raise
        serialised = json.dumps(snapshot)
        assert len(serialised) > 10

    def test_dump_contains_required_keys(self):
        agent = self._fresh_agent()
        snap = agent.dump()
        for key in ("alpha", "gamma", "epsilon", "actions", "q_table", "states_seen"):
            assert key in snap, f"Missing key: {key}"

    def test_dump_untrained_has_zero_states(self):
        agent = self._fresh_agent()
        snap = agent.dump()
        assert snap["states_seen"] == 0
        assert snap["q_table"] == {}

    def test_dump_trained_counts_states(self):
        agent = self._fresh_agent()
        for s in [(0, 0, 0, 0, 0), (1, 0, 1, 0, 1), (2, 1, 0, 1, 0)]:
            agent._ensure_state(s)
        snap = agent.dump()
        assert snap["states_seen"] == 3
        assert len(snap["q_table"]) == 3

    def test_dump_state_keys_are_strings(self):
        agent = self._fresh_agent()
        agent._ensure_state((1, 2, 0, 1, 0))
        snap = agent.dump()
        for k in snap["q_table"]:
            assert isinstance(k, str), f"Expected string key, got {type(k)}"

    def test_dump_state_key_format(self):
        agent = self._fresh_agent()
        agent._ensure_state((1, 2, 0, 1, 0))
        snap = agent.dump()
        assert "1|2|0|1|0" in snap["q_table"]


class TestAgentLoad:
    def _fresh_agent(self):
        from app.services.rl_agent import QLearningAgent
        return QLearningAgent()

    def _snapshot_with_q(self, state_key: str, action: str, value: float) -> dict:
        from app.services.rl_agent import QLearningAgent
        a = QLearningAgent()
        actions = {act: 0.0 for act in a.actions}
        actions[action] = value
        return {
            "alpha": 0.1, "gamma": 0.9, "epsilon": 0.05,
            "actions": a.actions,
            "q_table": {state_key: actions},
            "states_seen": 1,
        }

    def test_load_restores_epsilon(self):
        agent = self._fresh_agent()
        snap = self._snapshot_with_q("0|0|0|0|0", "NO_OP", 0.5)
        snap["epsilon"] = 0.03
        agent.load(snap)
        assert abs(agent.epsilon - 0.03) < 1e-9

    def test_load_restores_q_value(self):
        agent = self._fresh_agent()
        snap = self._snapshot_with_q("0|1|0|0|0", "DISABLE_INTERCEPT", 0.87)
        agent.load(snap)
        state = (0, 1, 0, 0, 0)
        assert abs(agent.q_table[state]["DISABLE_INTERCEPT"] - 0.87) < 1e-9

    def test_load_restores_state_count(self):
        agent = self._fresh_agent()
        snap = {
            "alpha": 0.1, "gamma": 0.9, "epsilon": 0.1,
            "actions": agent.actions,
            "q_table": {
                "0|0|0|0|0": {a: 0.0 for a in agent.actions},
                "1|0|1|0|1": {a: 0.5 for a in agent.actions},
            },
            "states_seen": 2,
        }
        agent.load(snap)
        assert len(agent.q_table) == 2

    def test_load_ignores_unknown_actions(self):
        """A snapshot with a 'FUTURE_ACTION' key must not crash the load."""
        agent = self._fresh_agent()
        snap = {
            "alpha": 0.1, "gamma": 0.9, "epsilon": 0.1,
            "actions": agent.actions,
            "q_table": {
                "0|0|0|0|0": {**{a: 0.1 for a in agent.actions}, "FUTURE_ACTION": 99.9}
            },
            "states_seen": 1,
        }
        agent.load(snap)  # must not raise
        state = (0, 0, 0, 0, 0)
        assert "FUTURE_ACTION" not in agent.q_table[state]

    def test_load_fills_missing_actions_with_zero(self):
        """Snapshot missing some actions still loads — missing ones default to 0."""
        agent = self._fresh_agent()
        snap = {
            "alpha": 0.1, "gamma": 0.9, "epsilon": 0.1,
            "actions": agent.actions,
            "q_table": {
                "0|0|0|0|0": {"NO_OP": 0.7}   # only one action present
            },
            "states_seen": 1,
        }
        agent.load(snap)
        state = (0, 0, 0, 0, 0)
        assert agent.q_table[state]["NO_OP"] == 0.7
        assert agent.q_table[state]["ENABLE_INTERCEPT"] == 0.0

    def test_load_overwrites_previous_q_table(self):
        agent = self._fresh_agent()
        agent._ensure_state((9, 9, 9, 9, 9))  # old state
        snap = self._snapshot_with_q("0|0|0|0|0", "NO_OP", 1.0)
        agent.load(snap)
        assert (9, 9, 9, 9, 9) not in agent.q_table
        assert (0, 0, 0, 0, 0) in agent.q_table

    def test_load_skips_bad_state_keys(self):
        """State keys that cannot be parsed as int tuples are silently skipped."""
        agent = self._fresh_agent()
        snap = {
            "alpha": 0.1, "gamma": 0.9, "epsilon": 0.1,
            "actions": agent.actions,
            "q_table": {
                "not_a_valid_key": {"NO_OP": 1.0},
                "0|0|0|0|0": {"NO_OP": 0.5},
            },
            "states_seen": 2,
        }
        agent.load(snap)
        assert len(agent.q_table) == 1  # only the valid one
        assert (0, 0, 0, 0, 0) in agent.q_table


class TestAgentIsTrainedFlag:
    def test_untrained_is_false(self):
        from app.services.rl_agent import QLearningAgent
        a = QLearningAgent()
        assert a.is_trained is False

    def test_trained_is_true(self):
        from app.services.rl_agent import QLearningAgent
        a = QLearningAgent()
        a._ensure_state((0, 0, 0, 0, 0))
        assert a.is_trained is True


class TestRoundTrip:
    """
    Full cycle: train an agent → dump → serialise to JSON string → parse →
    load into a fresh agent → verify decisions are deterministic and match.
    """

    def test_round_trip_preserves_best_action(self):
        from app.services.rl_agent import QLearningAgent

        # Lead agent — train it so DISABLE_INTERCEPT dominates for state (0,0,0,0,0)
        lead = QLearningAgent(epsilon=0.0)  # no exploration for predictability
        state = (0, 0, 0, 0, 0)
        lead._ensure_state(state)
        lead.q_table[state]["DISABLE_INTERCEPT"] = 5.0   # clearly best
        lead.q_table[state]["NO_OP"] = -1.0

        # Export
        snapshot_json = json.dumps(lead.dump())

        # Junior agent — starts completely fresh
        junior = QLearningAgent(epsilon=0.0)
        assert junior.is_trained is False

        # Import
        junior.load(json.loads(snapshot_json))
        assert junior.is_trained is True

        # Junior should now make the same decision as the lead
        assert junior.decide_action(state) == "DISABLE_INTERCEPT"

    def test_round_trip_multiple_states(self):
        from app.services.rl_agent import QLearningAgent

        lead = QLearningAgent(epsilon=0.0)
        scenarios = [
            ((0, 0, 0, 0, 0), "DISABLE_INTERCEPT", 3.0),
            ((1, 0, 1, 0, 0), "ENABLE_ACTIVE_SCAN", 2.5),
            ((2, 1, 0, 1, 1), "DECREASE_SCAN_SPEED", 4.0),
        ]
        for state, action, q in scenarios:
            lead._ensure_state(state)
            lead.q_table[state][action] = q

        junior = QLearningAgent(epsilon=0.0)
        junior.load(json.loads(json.dumps(lead.dump())))

        for state, expected_action, _ in scenarios:
            assert junior.decide_action(state) == expected_action, (
                f"State {state}: expected {expected_action}, "
                f"got {junior.decide_action(state)}"
            )


# ---------------------------------------------------------------------------
# Brain transfer through apply_team_profile
# ---------------------------------------------------------------------------

class TestBrainTransferViaProfile:
    """Verify that apply_team_profile injects the snapshot into the global agent."""

    def _conn_mock(self):
        cur = MagicMock()
        cur.fetchall.return_value = []
        cur.fetchone.return_value = None
        conn = MagicMock()
        conn.__enter__ = MagicMock(return_value=conn)
        conn.__exit__ = MagicMock(return_value=False)
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cur)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        return conn

    def _profile_with_brain(self, q_val: float) -> dict:
        from app.services.rl_agent import QLearningAgent
        a = QLearningAgent(epsilon=0.0)
        state = (0, 0, 0, 0, 0)
        a._ensure_state(state)
        a.q_table[state]["DISABLE_INTERCEPT"] = q_val
        return {
            "schema_version": "1.0",
            "profile_name": "Brain Test",
            "targets": [],
            "session_template": {},
            "proxy": {},
            "scanner_policy": {"preset_id": "balanced_audit"},
            "rl_settings": {},
            "rl_brain": a.dump(),
            "notes": "",
        }

    def test_brain_loaded_into_global_agent(self):
        from app.services import rl_agent as rl_mod
        from app.services.team_profile import apply_team_profile

        # Give the global agent a known state before import
        rl_mod.agent = rl_mod.QLearningAgent(epsilon=0.0)

        profile = self._profile_with_brain(q_val=9.9)

        with patch("app.services.team_profile.get_connection", return_value=self._conn_mock()), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert result["applied"] is True
        # The global agent should now know state (0,0,0,0,0) with high DISABLE_INTERCEPT
        assert rl_mod.agent.is_trained is True
        assert rl_mod.agent.decide_action((0, 0, 0, 0, 0)) == "DISABLE_INTERCEPT"

    def test_brain_status_in_result(self):
        from app.services import rl_agent as rl_mod
        from app.services.team_profile import apply_team_profile

        rl_mod.agent = rl_mod.QLearningAgent(epsilon=0.0)
        profile = self._profile_with_brain(q_val=1.0)

        with patch("app.services.team_profile.get_connection", return_value=self._conn_mock()), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert "rl_brain_status" in result
        status = result["rl_brain_status"]
        # Should mention states loaded, not "skipped"
        assert "skipped" not in status.lower()
        assert "loaded" in status.lower() or "state" in status.lower()

    def test_empty_brain_is_skipped_gracefully(self):
        from app.services import rl_agent as rl_mod
        from app.services.team_profile import apply_team_profile

        rl_mod.agent = rl_mod.QLearningAgent(epsilon=0.0)
        profile = {
            "schema_version": "1.0",
            "profile_name": "No Brain",
            "targets": [],
            "session_template": {},
            "proxy": {},
            "scanner_policy": {"preset_id": "balanced_audit"},
            "rl_settings": {},
            "rl_brain": {"states_seen": 0, "q_table": {}},
            "notes": "",
        }

        with patch("app.services.team_profile.get_connection", return_value=self._conn_mock()), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert result["applied"] is True
        # Empty brain → skipped, global agent stays untrained
        assert rl_mod.agent.is_trained is False
        assert "skipped" in result["rl_brain_status"].lower()

    def test_missing_brain_key_is_skipped_gracefully(self):
        from app.services import rl_agent as rl_mod
        from app.services.team_profile import apply_team_profile

        rl_mod.agent = rl_mod.QLearningAgent(epsilon=0.0)
        profile = {
            "schema_version": "1.0",
            "profile_name": "No Brain Key",
            "targets": [],
            "session_template": {},
            "proxy": {},
            "scanner_policy": {"preset_id": "balanced_audit"},
            "rl_settings": {},
            # no "rl_brain" key at all
            "notes": "",
        }

        with patch("app.services.team_profile.get_connection", return_value=self._conn_mock()), \
             patch("app.services.team_profile._user_has_active_session", return_value=True):
            result = apply_team_profile(1, profile)

        assert result["applied"] is True
        assert "skipped" in result["rl_brain_status"].lower()

    def test_export_includes_brain_key(self):
        """build_team_profile always includes an rl_brain section."""
        from app.services.team_profile import build_team_profile

        # Each DB call gets its own response:
        # call 1 → _get_username  → ("lead_user",)
        # call 2 → _get_session_template → None (no active session, uses defaults)
        call_count = [0]
        cur = MagicMock()

        def _fetchone():
            call_count[0] += 1
            if call_count[0] == 1:
                return ("lead_user",)
            return None  # no active session → template uses safe defaults

        cur.fetchone.side_effect = _fetchone
        cur.fetchall.return_value = []  # no websites

        conn = MagicMock()
        conn.__enter__ = MagicMock(return_value=conn)
        conn.__exit__ = MagicMock(return_value=False)
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cur)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        import flask
        app = flask.Flask("test_export")
        app.config.update(
            RL_TRUST_LOOPBACK_USER_ID=True,
            RL_ALLOW_ANON_LOOPBACK_EVENTS=True,
        )
        with app.app_context():
            with patch("app.services.team_profile.get_connection", return_value=conn):
                profile = build_team_profile(1)

        assert "rl_brain" in profile
        brain = profile["rl_brain"]
        assert "q_table" in brain
        assert "states_seen" in brain
        assert "epsilon" in brain
