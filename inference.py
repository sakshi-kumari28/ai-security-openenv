import json
import os
from typing import Any, Dict, List, Optional
from openai import OpenAI
from environment import AiSecurityEnv

API_KEY      = os.environ["API_KEY"]
API_BASE_URL = os.environ["API_BASE_URL"]
MODEL_NAME   = os.getenv("MODEL_NAME", "gpt-4o-mini")
TASK_NAME    = os.getenv("TASK_NAME", "data_leakage_prevention")
BENCHMARK    = "ai-security-openenv"
MAX_STEPS    = 1

client = OpenAI(api_key=API_KEY, base_url=API_BASE_URL)

SYSTEM_PROMPT = ("You are an AI security agent. Respond with JSON only. Format: {\"allow\": true, \"threat_type\": \"none\", \"response_action\": \"allow\"}")

def log_start(task, env, model):
    print("[START] task=" + task + " env=" + env + " model=" + model, flush=True)

def log_step(step, action, reward, done, error):
    e = error if error else "null"
    d = "true" if done else "false"
    print("[STEP] step=" + str(step) + " action=" + str(action) + " reward=" + "{:.2f}".format(reward) + " done=" + d + " error=" + e, flush=True)

def log_end(success, steps, score, rewards):
    s = "true" if success else "false"
    r = ",".join("{:.2f}".format(x) for x in rewards)
    print("[END] success=" + s + " steps=" + str(steps) + " score=" + "{:.2f}".format(score) + " rewards=" + r, flush=True)

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
        temperature=0.0,
        max_tokens=256,
    )
    raw = response.choices[0].message.content.strip()
    raw = raw.replace("```json", "").replace("```", "").strip()
    return json.loads(raw)

def run_task_with_logging(task_name=TASK_NAME):
    log_start(task_name, BENCHMARK, MODEL_NAME)
    env = AiSecurityEnv()
    state = env.reset()
    rewards = []
    score = 0.0
    success = False
    for step in range(1, MAX_STEPS + 1):
        error = None
        reward = 0.0
        done = False
        try:
            action = call_llm(state)
            observation, reward, done, info = env.step(action)
            score = reward
            success = reward >= 0.5
            action_str = json.dumps(action)
        except Exception as exc:
            error = str(exc)[:80]
            reward = -0.2
            done = True
            action_str = "error"
        rewards.append(reward)
        log_step(step, action_str, reward, done, error)
        if done:
            break
    log_end(success, MAX_STEPS, score, rewards)
    return score

if __name__ == "__main__":
    run_task_with_logging()
