from flask import Flask, request, jsonify
from app.services.rl_agent import QLearningAgent, ALL_ACTIONS


app = Flask(__name__)

# ----------------------------
# Initialize ONE global RL agent
# ----------------------------
agent = QLearningAgent()

# ----------------------------
# Helper: build state tuple
# ----------------------------
def build_state(data):
    """
    Expected JSON fields:
    response_class        -> int (0=2xx, 1=4xx, 2=5xx)
    scan_speed            -> int (0=Fast, 1=Slow)
    issue_confidence      -> int (0=MostlyHigh, 1=MostlyLow)
    issue_volume          -> int (0=Few, 1=Many)
    false_positive_rate   -> int (0=Low, 1=High)
    """
    return (
        int(data["response_class"]),
        int(data["scan_speed"]),
        int(data["issue_confidence"]),
        int(data["issue_volume"]),
        int(data["false_positive_rate"]),
    )

# ----------------------------
# API endpoint
# ----------------------------
@app.route("/decide-action", methods=["POST"])
def decide_action():
    payload = request.get_json()

    if payload is None:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    try:
        state = build_state(payload)

        # Optional reward (can be 0 for now)
        reward = float(payload.get("reward", 0))

        # Select action
        action = agent.select_action(state)

        # Update agent if next_state provided
        if "next_state" in payload:
            next_state = build_state(payload["next_state"])
            agent.update(state, action, reward, next_state)

        agent.decay_epsilon()

        return jsonify({
            "action_id": action,
            "epsilon": agent.epsilon
        })

    except KeyError as e:
        return jsonify({"error": f"Missing field: {e}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500



