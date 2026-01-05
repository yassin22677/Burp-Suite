from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Tuple, List
import random

# ---------- Discrete encodings ----------
# response_class: 0=2xx, 1=4xx, 2=5xx
# scan_speed:     0=Fast, 1=Slow
# conf:           0=MostlyHigh, 1=MostlyLow
# issue_volume:   0=Few, 1=Many
# fp_rate:        0=Low, 1=High

State = Tuple[int, int, int, int, int]

# Actions (fixed IDs)
A_DO_NOTHING = 0
A_INC_THRESHOLD = 1
A_DEC_THRESHOLD = 2
A_ENABLE_ACTIVE = 3
A_DISABLE_ACTIVE = 4
A_EXPAND_SCOPE = 5
A_REDUCE_SCOPE = 6

ALL_ACTIONS: List[int] = [
    A_DO_NOTHING,
    A_INC_THRESHOLD,
    A_DEC_THRESHOLD,
    A_ENABLE_ACTIVE,
    A_DISABLE_ACTIVE,
    A_EXPAND_SCOPE,
    A_REDUCE_SCOPE
]
@dataclass
class QLearningAgent:
    alpha: float = 0.2     # learning rate
    gamma: float = 0.95    # discount factor
    epsilon: float = 0.7   # exploration probability
    epsilon_min: float = 0.05
    epsilon_decay: float = 0.995

    # Q-table: maps state -> maps action -> Q value
    Q: Dict[State, Dict[int, float]] = None

    def __post_init__(self):
        if self.Q is None:
            self.Q = {}

    def _ensure_state(self, s: State):
        if s not in self.Q:
            self.Q[s] = {a: 0.0 for a in ALL_ACTIONS}

    def select_action(self, s: State) -> int:
        """ε-greedy action selection."""
        self._ensure_state(s)

        if random.random() < self.epsilon:
            return random.choice(ALL_ACTIONS)

        # exploit: choose argmax Q(s,a)
        best_action = max(self.Q[s], key=self.Q[s].get)
        return best_action

    def update(self, s: State, a: int, r: float, s_next: State, done: bool = False):
        """Q-learning update: Q(s,a) <- Q(s,a) + α [r + γ max_a' Q(s',a') - Q(s,a)]"""
        self._ensure_state(s)
        self._ensure_state(s_next)

        current_q = self.Q[s][a]
        next_max = 0.0 if done else max(self.Q[s_next].values())
        target = r + self.gamma * next_max
        self.Q[s][a] = current_q + self.alpha * (target - current_q)

    def decay_epsilon(self):
        """Reduce exploration gradually."""
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
def random_state() -> State:
    return (
        random.randint(0, 2),  # response_class
        random.randint(0, 1),  # scan_speed
        random.randint(0, 1),  # conf
        random.randint(0, 1),  # issue_volume
        random.randint(0, 1),  # fp_rate
    )

def toy_reward(s: State, a: int) -> float:
    """Fake reward to test learning. Replace in Step 5 with Burp-derived reward."""
    response_class, scan_speed, conf, issue_volume, fp = s

    r = 0.0
    # Encourage fewer false positives and better confidence
    if fp == 0:
        r += 1.0
    if conf == 0:
        r += 2.0

    # If slow scans, prefer decreasing intensity (example heuristic)
    if scan_speed == 1 and a in (A_DEC_THRESHOLD, A_DISABLE_ACTIVE, A_REDUCE_SCOPE):
        r += 2.0
    if scan_speed == 1 and a in (A_INC_THRESHOLD, A_ENABLE_ACTIVE, A_EXPAND_SCOPE):
        r -= 1.0

    return r

if __name__ == "__main__":
    agent = QLearningAgent()

    for episode in range(200):
        s = random_state()
        for t in range(30):
            a = agent.select_action(s)
            r = toy_reward(s, a)
            s_next = random_state()
            agent.update(s, a, r, s_next, done=False)
            s = s_next
        agent.decay_epsilon()

    # print a sample learned policy for one state
    test_s = (0, 1, 1, 0, 1)  # example state
    agent._ensure_state(test_s)
    print("Epsilon:", agent.epsilon)
    print("Q-values:", agent.Q[test_s])
    print("Best action:", max(agent.Q[test_s], key=agent.Q[test_s].get))

    
if __name__ == "__main__":
    # temporary test
    ...
