# app/services/rl_agent.py

import random


class QLearningAgent:
    """
    Simple Q-Learning agent for Burp Suite configuration tuning.

    - Uses a dictionary as Q-table
    - State is a tuple (must be hashable)
    - Actions are STRING names (important for Burp + dashboard)
    """

    def __init__(
        self,
        alpha=0.1,     # learning rate
        gamma=0.9,     # discount factor
        epsilon=0.1    # exploration rate
    ):
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon

        # Q-table: { state: { action_name: q_value } }
        self.q_table = {}

        # ALL actions must be STRINGS
        self.actions = [
            "NO_OP",
            "ENABLE_INTERCEPT",
            "DISABLE_INTERCEPT",
            "INCREASE_SCAN_SPEED",
            "DECREASE_SCAN_SPEED",
            "ENABLE_ACTIVE_SCAN",
            "DISABLE_ACTIVE_SCAN",
        ]

    # --------------------------------------------------
    # INTERNAL: ensure state exists in Q-table
    # --------------------------------------------------
    def _ensure_state(self, state):
        if state not in self.q_table:
            self.q_table[state] = {a: 0.0 for a in self.actions}

    # --------------------------------------------------
    # DECIDE ACTION (used by /decide-action)
    # --------------------------------------------------
    def decide_action(self, state):
        """
        Chooses an action name (STRING) using epsilon-greedy policy.
        """
        self._ensure_state(state)

        # Exploration
        if random.random() < self.epsilon:
            action = random.choice(self.actions)
        else:
            # Exploitation
            action = max(
                self.q_table[state],
                key=self.q_table[state].get
            )

        return action  # MUST be string

    # --------------------------------------------------
    # UPDATE Q-TABLE (used by /update-reward)
    # --------------------------------------------------
    def update(self, state, action, reward, next_state):
        """
        Standard Q-learning update rule.
        """
        self._ensure_state(state)
        self._ensure_state(next_state)

        old_q = self.q_table[state][action]
        best_next_q = max(self.q_table[next_state].values())

        new_q = old_q + self.alpha * (
            reward + self.gamma * best_next_q - old_q
        )

        self.q_table[state][action] = new_q

    # --------------------------------------------------
    # EXPLORATION DECAY
    # --------------------------------------------------
    def decay_epsilon(self, min_epsilon: float = 0.01, decay: float = 0.995) -> None:
        """Reduce exploration rate after each step (standard schedule)."""
        self.epsilon = max(min_epsilon, self.epsilon * decay)

    # --------------------------------------------------
    # SERIALISATION — export / import the learned brain
    # --------------------------------------------------
    def dump(self) -> dict:
        """
        Return a JSON-safe snapshot of the agent's full learned state.
        Tuple keys are converted to pipe-joined strings so they survive JSON
        round-trips without any custom encoder.
        """
        return {
            "alpha": self.alpha,
            "gamma": self.gamma,
            "epsilon": self.epsilon,
            "actions": list(self.actions),
            "q_table": {
                "|".join(str(v) for v in state): dict(action_values)
                for state, action_values in self.q_table.items()
            },
            "states_seen": len(self.q_table),
        }

    def load(self, snapshot: dict) -> None:
        """
        Restore the agent from a snapshot produced by :meth:`dump`.
        Unknown action keys in the snapshot are ignored so old snapshots are
        forward-compatible when new actions are added.
        """
        self.alpha   = float(snapshot.get("alpha",   self.alpha))
        self.gamma   = float(snapshot.get("gamma",   self.gamma))
        self.epsilon = float(snapshot.get("epsilon", self.epsilon))

        raw = snapshot.get("q_table") or {}
        restored: dict = {}
        for state_str, action_values in raw.items():
            # Rebuild the tuple key: "0|1|0|0|1" → (0, 1, 0, 0, 1)
            try:
                state_tuple = tuple(int(x) for x in state_str.split("|"))
            except ValueError:
                continue
            if not isinstance(action_values, dict):
                continue
            # Start from defaults so all current actions have a value
            entry = {a: 0.0 for a in self.actions}
            for action, q_val in action_values.items():
                if action in entry:
                    try:
                        entry[action] = float(q_val)
                    except (TypeError, ValueError):
                        pass
            restored[state_tuple] = entry

        self.q_table = restored

    @property
    def is_trained(self) -> bool:
        """True if the agent has seen at least one state."""
        return bool(self.q_table)


# =====================================================
# ✅ SINGLE GLOBAL AGENT INSTANCE (CRITICAL)
# =====================================================
agent = QLearningAgent()
