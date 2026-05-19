"""
Verification script for the team-profile + RL agent wiring.

Run from the repo root with the server already started:

    python scripts/verify_team_profile.py

What it checks
--------------
1. DB connectivity — can we reach PostgreSQL?
2. Websites table — how many targets exist for your user?
3. Agent wiring  — does /decide-action call the real Q-agent (not the hash)?
4. Learning loop — does /update-reward grow the Q-table?
5. Brain export  — does GET /api/team/profile/export include rl_brain?
6. Brain import  — does POST /api/team/profile/import load Q-values into the agent?
7. Round-trip    — after import, does the agent make trained decisions?

The script talks to http://127.0.0.1:5000 directly using requests.
You must be logged in first — it reads your session cookie from the server
by doing a quick /auth/login with credentials you supply (or uses env vars).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Make sure repo root is on sys.path
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

BASE = "http://127.0.0.1:5000"
SEP  = "─" * 60

# ---------------------------------------------------------------------------
# Credentials — edit or set env vars VERIFY_USER / VERIFY_PASS
# ---------------------------------------------------------------------------
USERNAME = os.environ.get("VERIFY_USER", "rawan22")
PASSWORD = os.environ.get("VERIFY_PASS", "")   # set VERIFY_PASS in your shell


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok(msg: str)  -> None: print(f"  ✓  {msg}")
def fail(msg: str)-> None: print(f"  ✗  {msg}")
def info(msg: str)-> None: print(f"  ·  {msg}")
def head(msg: str)-> None: print(f"\n{SEP}\n{msg}\n{SEP}")


def login(session: requests.Session) -> bool:
    if not PASSWORD:
        print("\n  [!] Set VERIFY_PASS env var to your password so the script can log in.")
        print("      Example (PowerShell):")
        print('          $env:VERIFY_PASS="yourpassword"')
        print("          python scripts/verify_team_profile.py")
        return False
    r = session.post(
        f"{BASE}/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
        timeout=5,
    )
    if r.status_code == 200:
        ok(f"Logged in as '{USERNAME}'")
        return True
    fail(f"Login failed {r.status_code}: {r.text[:120]}")
    return False


# ---------------------------------------------------------------------------
# Check 1 — server reachable
# ---------------------------------------------------------------------------
def check_server() -> bool:
    head("CHECK 1 — Server reachable at http://127.0.0.1:5000")
    try:
        r = requests.get(f"{BASE}/", timeout=3)
        ok(f"Server responded HTTP {r.status_code}")
        return True
    except requests.ConnectionError:
        fail("Cannot reach the server. Start it with:  python run.py")
        return False


# ---------------------------------------------------------------------------
# Check 2 — PostgreSQL / websites table
# ---------------------------------------------------------------------------
def check_db(session: requests.Session) -> None:
    head("CHECK 2 — Database: websites table for your user")
    try:
        from app.services.postgres import get_connection
        import flask, app as app_pkg
        flask_app = app_pkg.create_app()
        with flask_app.app_context():
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, base_url, environment FROM websites "
                        "WHERE user_id = (SELECT id FROM users WHERE username=%s) "
                        "ORDER BY id DESC LIMIT 10",
                        (USERNAME,),
                    )
                    rows = cur.fetchall()
        if rows:
            ok(f"Found {len(rows)} target(s) in websites table for '{USERNAME}':")
            for row in rows:
                info(f"  id={row[0]}  url={row[1]}  env={row[2]}")
        else:
            info(f"No websites rows found for '{USERNAME}' — import a profile to add some.")
    except Exception as exc:
        fail(f"DB check failed: {exc}")


# ---------------------------------------------------------------------------
# Check 3 — /decide-action uses the real agent
# ---------------------------------------------------------------------------
def check_decide_action(session: requests.Session) -> tuple[int, str]:
    head("CHECK 3 — /decide-action wiring (real Q-agent, not hash)")
    from app.services.rl_agent import agent as global_agent

    states_before = len(global_agent.q_table)
    info(f"Agent Q-table size before call: {states_before} state(s)")

    payload = {"status": 200, "method": "GET", "url": "https://dvwa.example.com/login", "reward": 0}
    r = session.post(f"{BASE}/decide-action", json=payload, timeout=5)

    if r.status_code != 200:
        fail(f"HTTP {r.status_code}: {r.text[:120]}")
        return -1, ""

    action_idx_str = r.text.strip()
    states_after = len(global_agent.q_table)

    if not action_idx_str.isdigit():
        fail(f"Response is not a digit: {action_idx_str!r}  (hash stub still active?)")
        return -1, ""

    action_idx = int(action_idx_str)
    from app.views.rl_burp_routes import ACTION_NAMES
    action_name = ACTION_NAMES[action_idx] if 0 <= action_idx < len(ACTION_NAMES) else "?"

    if states_after > states_before:
        ok(f"Agent registered a new state → Q-table grew {states_before} → {states_after}")
    else:
        info(f"State was already known (Q-table stays at {states_after})")

    ok(f"Action returned: {action_idx} ({action_name})")
    ok(f"Agent epsilon: {global_agent.epsilon:.4f}")
    return action_idx, action_name


# ---------------------------------------------------------------------------
# Check 4 — /update-reward grows the Q-table
# ---------------------------------------------------------------------------
def check_update_reward(session: requests.Session) -> None:
    head("CHECK 4 — /update-reward closes the learning loop")
    from app.services.rl_agent import agent as global_agent

    states_before = len(global_agent.q_table)
    epsilon_before = global_agent.epsilon

    r = session.post(f"{BASE}/update-reward", json={"reward": 1, "status": 200, "method": "GET"}, timeout=5)

    if r.status_code != 200:
        fail(f"HTTP {r.status_code}: {r.text[:120]}")
        return

    data = r.json()
    if data.get("status") != "ok":
        fail(f"Unexpected response: {data}")
        return

    reported = data.get("states_trained", "?")
    actual   = len(global_agent.q_table)
    epsilon_after = global_agent.epsilon

    ok(f"Response: {data}")
    ok(f"states_trained reported by server: {reported}")
    ok(f"Q-table size in memory: {actual}")

    if epsilon_after < epsilon_before:
        ok(f"Epsilon decayed: {epsilon_before:.4f} → {epsilon_after:.4f}  (agent is learning)")
    else:
        info(f"Epsilon unchanged at {epsilon_after:.4f}")


# ---------------------------------------------------------------------------
# Check 5 — export includes rl_brain
# ---------------------------------------------------------------------------
def check_export(session: requests.Session) -> dict:
    head("CHECK 5 — GET /api/team/profile/export includes rl_brain")
    r = session.get(f"{BASE}/api/team/profile/export?name=verify_test", timeout=5)

    if r.status_code == 401:
        fail("Not authenticated — log in first")
        return {}
    if r.status_code != 200:
        fail(f"HTTP {r.status_code}: {r.text[:120]}")
        return {}

    try:
        profile = r.json()
    except Exception:
        fail("Response is not valid JSON")
        return {}

    # Check required top-level keys
    required = ["schema_version", "targets", "session_template",
                "proxy", "scanner_policy", "rl_settings", "rl_brain"]
    missing = [k for k in required if k not in profile]
    if missing:
        fail(f"Missing keys in export: {missing}")
    else:
        ok("All required keys present in export")

    brain = profile.get("rl_brain", {})
    states = brain.get("states_seen", 0)
    epsilon = brain.get("epsilon", "?")
    q_keys  = len(brain.get("q_table", {}))

    ok(f"rl_brain.states_seen = {states}")
    ok(f"rl_brain.epsilon     = {epsilon}")
    ok(f"rl_brain.q_table     = {q_keys} state(s) in JSON")

    if states == 0:
        info("Brain is still 0 — this export was made before Burp sent any traffic.")
        info("Start a scan session, let Burp process some requests, then export again.")
    else:
        ok(f"Brain has {states} trained state(s) — junior testers will inherit this knowledge.")

    targets = profile.get("targets", [])
    info(f"Targets in export: {len(targets)}")
    for t in targets[:5]:
        info(f"  + {t.get('base_url')}  ({t.get('environment')})")

    return profile


# ---------------------------------------------------------------------------
# Check 6 + 7 — import injects Q-values into the global agent
# ---------------------------------------------------------------------------
def check_import_and_round_trip(session: requests.Session, profile: dict) -> None:
    head("CHECK 6+7 — POST /api/team/profile/import + round-trip decision")
    from app.services import rl_agent as rl_mod

    # Inject a known Q-value directly into the profile brain
    test_state_key = "0|0|0|0|0"   # (2xx, GET, short-url, 0, 0)
    test_action    = "DISABLE_INTERCEPT"
    test_q_value   = 9.9            # dominant — agent must pick this

    injected_brain = {
        "alpha": 0.1, "gamma": 0.9, "epsilon": 0.05,
        "actions": rl_mod.agent.actions,
        "q_table": {test_state_key: {a: (test_q_value if a == test_action else 0.0)
                                     for a in rl_mod.agent.actions}},
        "states_seen": 1,
    }
    test_profile = {**profile, "rl_brain": injected_brain}

    # Reset the global agent to untrained before import
    rl_mod.agent = rl_mod.QLearningAgent()
    info(f"Agent reset to untrained (states={len(rl_mod.agent.q_table)})")

    r = session.post(
        f"{BASE}/api/team/profile/import",
        json=test_profile,
        timeout=5,
    )
    if r.status_code not in (200, 201):
        fail(f"Import HTTP {r.status_code}: {r.text[:120]}")
        return

    result = r.json()
    brain_status = result.get("rl_brain_status", "")
    ok(f"Import result: {result.get('applied')}")
    ok(f"rl_brain_status: {brain_status}")

    if "skipped" in brain_status.lower():
        fail("Brain was skipped — something went wrong")
        return

    # Verify the global agent was actually updated
    state_tuple = tuple(int(x) for x in test_state_key.split("|"))
    if state_tuple not in rl_mod.agent.q_table:
        fail(f"State {state_tuple} not in agent Q-table after import")
        return

    loaded_q = rl_mod.agent.q_table[state_tuple][test_action]
    ok(f"Q-value for ({test_state_key}, {test_action}) = {loaded_q}  (expected {test_q_value})")
    assert abs(loaded_q - test_q_value) < 1e-6, "Q-value mismatch!"

    # Round-trip: ask the agent to decide — it must pick DISABLE_INTERCEPT
    rl_mod.agent.epsilon = 0.0   # no exploration
    chosen = rl_mod.agent.decide_action(state_tuple)
    if chosen == test_action:
        ok(f"Round-trip PASSED — agent chose '{chosen}' (same as lead's trained preference)")
    else:
        fail(f"Round-trip FAILED — expected '{test_action}', got '{chosen}'")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("\n" + "═" * 60)
    print("  TEAM PROFILE + RL AGENT VERIFICATION")
    print("═" * 60)

    if not check_server():
        sys.exit(1)

    sess = requests.Session()
    if not login(sess):
        sys.exit(1)

    check_db(sess)
    check_decide_action(sess)
    check_update_reward(sess)
    profile = check_export(sess)
    if profile:
        check_import_and_round_trip(sess, profile)

    print(f"\n{'═'*60}")
    print("  Done. Review any ✗ lines above.")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    main()
