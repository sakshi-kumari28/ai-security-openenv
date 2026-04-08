import json
import random
from dataclasses import dataclass
from enum import Enum
from flask import Flask, request, jsonify

app = Flask(__name__)

class DataSensitivity(Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"

class ThreatType(Enum):
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE       = "brute_force"
    INTRUSION         = "intrusion"
    NONE              = "none"

@dataclass
class SecurityEvent:
    event_id:         str
    logs:             list
    user_role:        str
    data_sensitivity: str
    status:           str = "open"
    decision:         object = None

    def to_dict(self):
        return {
            "event_id":         self.event_id,
            "logs":             self.logs,
            "user_role":        self.user_role,
            "data_sensitivity": self.data_sensitivity,
            "status":           self.status,
            "decision":         self.decision,
        }

class AiSecurityEnv:
    def __init__(self, seed=42):
        self.seed = seed
        random.seed(seed)
        self.current_event = None
        self.step_count = 0
        self.max_steps = 10
        self.task_scenarios = self._initialize_scenarios()

    def _initialize_scenarios(self):
        return [
            {
                "name": "Data Leakage Prevention",
                "difficulty": "easy",
                "event_id": "EVT-001",
                "logs": ["User initiated data export", "2GB data transfer to external IP"],
                "user_role": "employee",
                "data_sensitivity": "high",
                "expected": {"allow": False, "threat_type": "data_exfiltration", "response_action": "block"},
            },
            {
                "name": "Threat Detection",
                "difficulty": "medium",
                "event_id": "EVT-002",
                "logs": ["Failed login attempt from 192.168.1.50", "Failed login attempt from 192.168.1.50", "Failed login attempt from 192.168.1.50", "Successful login from 192.168.1.50"],
                "user_role": "unknown",
                "data_sensitivity": "medium",
                "expected": {"allow": False, "threat_type": "brute_force", "response_action": "block_ip"},
            },
            {
                "name": "Advanced Threat Response",
                "difficulty": "hard",
                "event_id": "EVT-003",
                "logs": ["Unusual data transfer volume detected", "Access from unknown IP 203.0.113.45", "Admin login at 02:30 UTC (outside business hours)", "Database query on sensitive customer records"],
                "user_role": "admin",
                "data_sensitivity": "high",
                "expected": {"allow": False, "threat_type": "intrusion", "response_action": "block + alert", "firewall_rule": {"rule_action": "block", "target": "ip", "duration": "24h"}},
            },
        ]

    def reset(self):
        self.step_count = 0
        scenario = random.choice(self.task_scenarios)
        self.current_event = SecurityEvent(
            event_id=scenario["event_id"],
            logs=scenario["logs"],
            user_role=scenario["user_role"],
            data_sensitivity=scenario["data_sensitivity"],
        )
        return self._get_state()

    def state(self):
        return self._get_state()

    def step(self, action):
        self.step_count += 1
        if not isinstance(action, dict):
            return self._get_state(), -0.2, True, {"error": "Invalid action"}
        grade = self._grade_action(action)
        reward = grade["reward"]
        done = (reward >= 0.5) or (self.step_count >= self.max_steps)
        if done and self.current_event:
            self.current_event.status = "processed"
            self.current_event.decision = action
        return self._get_state(), reward, done, {"grade": grade, "step": self.step_count, "done": done}

    def _get_state(self):
        if self.current_event is None:
            raise RuntimeError("Call reset() first.")
        return self.current_event.to_dict()

    def _grade_action(self, action):
        if self.current_event is None:
            return {"score": 0.0, "reward": 0.0, "details": {}}
        scenario = self._find_current_scenario()
        if scenario is None:
            return {"score": 0.0, "reward": 0.0, "details": {}}
        expected = scenario["expected"]
        total_score = 0.0
        total_score += (1.0 if action.get("allow") == expected["allow"] else 0.0) * 0.3
        total_score += (1.0 if action.get("threat_type") == expected["threat_type"] else 0.0) * 0.3
        total_score += (1.0 if action.get("response_action") == expected["response_action"] else 0.0) * 0.2
        firewall_score = 0.0
        if "firewall_rule" in expected:
            er = expected["firewall_rule"]
            ar = action.get("firewall_rule", {})
            if isinstance(ar, dict) and ar.get("rule_action") == er.get("rule_action") and ar.get("target") == er.get("target") and ar.get("duration") == er.get("duration"):
                firewall_score = 1.0
        elif action.get("firewall_rule") is None:
            firewall_score = 1.0
        total_score += firewall_score * 0.2
        step_penalty = max(0, (self.step_count - 1) * 0.05)
        final_score = max(0.0, total_score - step_penalty)
        return {"score": round(final_score, 4), "reward": round(final_score, 4), "details": {}, "step_penalty": step_penalty}

    def _find_current_scenario(self):
        if self.current_event is None:
            return None
        for s in self.task_scenarios:
            if s["event_id"] == self.current_event.event_id:
                return s
        return None


env = AiSecurityEnv()


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "AI Security OpenEnv is running"}), 200

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"}), 200

@app.route("/reset", methods=["POST"])
def reset_route():
    try:
        return jsonify(env.reset()), 200
    except Exception as e:
        return jsonify({"type": "error", "error": {"message": str(e)}}), 500

@app.route("/step", methods=["POST"])
def step_route():
    try:
        action = request.get_json(force=True)
        if action is None:
            return jsonify({"type": "error", "error": {"message": "No JSON body"}}), 400
        observation, reward, done, info = env.step(action)
        return jsonify({"observation": observation, "reward": reward, "done": done, "info": info}), 200
    except Exception as e:
        return jsonify({"type": "error", "error": {"message": str(e)}}), 500

@app.route("/state", methods=["GET"])
def state_route():
    try:
        return jsonify(env.state()), 200
    except RuntimeError:
        return jsonify(env.reset()), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860, debug=False)
