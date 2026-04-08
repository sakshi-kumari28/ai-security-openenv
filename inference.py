import json
import os
from openai import OpenAI
from environment import AiSecurityEnv

API_KEY      = os.environ["API_KEY"]
API_BASE_URL = os.environ["API_BASE_URL"]
MODEL_NAME   = os.getenv("MODEL_NAME", "gpt-4o-mini")
BENCHMARK    = "ai-security-openenv"

client = OpenAI(api_key=API_KEY, base_url=API_BASE_URL)

SYSTEM_PROMPT = ("You are an AI security agent. Respond with JSON only, no explanation. Use this format exactly: {\"allow\": false, \"threat_type\": \"data_exfiltration\", \"response_action\": \"block\"}")

TASKS = [
    "data_leakage_prevention",
    "threat_detection",
    "advanced_threat_response",
]

def log_start(task, env, model):
    print("[START] task=" + task + " env=" + env + " model=" + model, flush=True)

def log_step(step, action, reward, done, error):
    e = error if error else "null"
    d = "true" if done else "false"
    print("[STEP] step=" + str(step) + " action=" + str(action) + " reward=" + "{:.2f}".format(reward) + " done=" + d + " error=" + e, flush=True)

def log_end(success, steps, score, rewards):
    s = "true" if success else "false"
    r = ",".join("{:.2f}".format(x) for x in rewards)
    print("[END] success=" + s + " steps=" + str(steps) + " score=" + "{:.4f}".format(score) + " rewards=" + r, flush=True)

def clamp(score):
    return max(0.001, min(0.999, float(score)))

def call_llm(state):
    prompt = json.dumps({
        "event_id": state.get("event_id"),
        "logs": state.get("logs", []),
        "data_sensitivity": state.get("data_sensitivity", "low"),
        "user_role": state.get("user_role"),
    }, indent=2)
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=256,
    )
    raw = response.choices[0].message.content.strip()
    raw = raw.replace("```json", "").replace("```", "").strip()
    return json.loads(raw)

def run_task(task_name, env):
    log_start(task_name, BENCHMARK, MODEL_NAME)
    state = env.reset()
    rewards = []
    score = 0.0
    success = False
    error = None
    try:
        action = call_llm(state)
        observation, reward, done, info = env.step(action)
        score = clamp(reward)
        success = score >= 0.5
        action_str = json.dumps(action)
    except Exception as exc:
        error = str(exc)[:80]
        reward = 0.1
        score = 0.1
        done = True
        action_str = "error"
    rewards.append(score)
    log_step(1, action_str, score, True, error)
    log_end(success, 1, score, rewards)
    return score

if __name__ == "__main__":
    env = AiSecurityEnv()
    for task in TASKS:
        run_task(task, env)
