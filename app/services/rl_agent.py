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


# =====================================================
# ✅ SINGLE GLOBAL AGENT INSTANCE (CRITICAL)
# =====================================================
agent = QLearningAgent()
