---
title: AI Security OpenEnv
emoji: 🔐
colorFrom: blue
colorTo: red
sdk: docker
pinned: false
---

title: AI Security OpenEnv
emoji: 🔐
colorFrom: red
colorTo: blue
sdk: docker
app_file: app.py
pinned: false
🔐 AI Security Policy Enforcement & Firewall Optimization (OpenEnv)
📌 Overview
This project implements a production-ready OpenEnv environment for evaluating AI agents in cybersecurity workflows. The environment simulates real-world scenarios where an AI agent must detect threats, prevent data leakage, and dynamically generate firewall rules.
Built for the Scaler Meta PyTorch Hackathon — OpenEnv track.

🤗 HuggingFace Space: mveekshan12/ai-security-openenv
💻 GitHub: sakshi-kumari28/ai-security-openenv


🚀 Quick Start
Prerequisites

Python >= 3.11
Docker
HuggingFace account

Installation
bashgit clone https://github.com/sakshi-kumari28/ai-security-openenv.git
cd ai-security-openenv
pip install -r requirements.txt
Running Locally
bash# Start the Flask server
python environment.py
bash# Run inference
export HF_TOKEN=your_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
python inference.py

📁 Project Structure
ai-security-openenv/
├── environment.py       # Flask server + OpenEnv environment
├── inference.py         # OpenAI-compatible inference script
├── app.py               # App entry point
├── server/
│   ├── __init__.py
│   └── app.py           # Server entry point for multi-mode deployment
├── tasks.py             # Task definitions and grading
├── openenv.yaml         # OpenEnv specification
├── Dockerfile           # Docker configuration
├── requirements.txt     # Python dependencies
├── pyproject.toml       # Project metadata and scripts
└── uv.lock              # Dependency lock file

🎯 Tasks
1. Data Leakage Prevention (Easy)

Event: User attempts to transfer 2GB of data to an external IP
Expected Decision: Block the transfer
Threat Type: data_exfiltration
Response Action: block
Max Reward: 1.0

2. Threat Detection - Brute Force (Medium)

Event: Multiple failed login attempts followed by a successful login
Expected Decision: Block the IP
Threat Type: brute_force
Response Action: block_ip
Max Reward: 1.0

3. Advanced Threat Response - Intrusion (Hard)

Event: Unusual data transfer + unknown IP + admin login at 02:30 UTC + sensitive DB query
Expected Decision: Block and alert
Threat Type: intrusion
Response Action: block + alert
Firewall Rule: block IP for 24h
Max Reward: 1.0


🏗️ Architecture
Environment (environment.py)

Flask HTTP server running on port 7860
OpenEnv-compliant API endpoints
Deterministic grading engine with partial rewards
Seeded randomization for reproducibility

API Endpoints
EndpointMethodDescription/GETHealth check — returns 200 OK/healthGETStatus check/resetPOSTReset environment, returns initial state/stepPOSTExecute action, returns observation + reward/stateGETGet current environment state
Scoring Weights
FieldWeightDescriptionallow0.3Correct allow/block decisionthreat_type0.3Correct threat classificationresponse_action0.2Correct response actionfirewall_rule0.2Correct firewall rule (when applicable)

🔧 Environment Variables
VariableDescriptionExampleAPI_BASE_URLLLM API endpointhttps://router.huggingface.co/v1MODEL_NAMEModel identifierQwen/Qwen2.5-72B-InstructHF_TOKENHuggingFace API tokenhf_xxx...

📊 Inference Script
The inference script uses the OpenAI client and follows the required stdout format:
[START] task=data_leakage_prevention env=ai-security-openenv model=Qwen/Qwen2.5-72B-Instruct
[STEP] step=1 action={"allow": false, "threat_type": "data_exfiltration", "response_action": "block"} reward=0.80 done=true error=null
[END] success=true steps=1 score=0.80 rewards=0.80

🔍 Action Schema
json{
  "allow": false,
  "threat_type": "data_exfiltration",
  "response_action": "block",
  "firewall_rule": {
    "rule_action": "block",
    "target": "ip",
    "duration": "24h"
  }
}

📋 State Schema
json{
  "event_id": "EVT-001",
  "logs": ["User initiated data export", "2GB data transfer to external IP"],
  "user_role": "employee",
  "data_sensitivity": "high",
  "status": "open",
  "decision": null
}

🐳 Docker
bash# Build
docker build -t ai-security-openenv .

# Run
docker run -p 7860:7860 ai-security-openenv

✅ OpenEnv Compliance Checklist

✅ POST /reset endpoint returns valid JSON state
✅ POST /step endpoint accepts action and returns reward
✅ GET /state endpoint returns current state
✅ GET / returns 200 OK for ping check
✅ Deterministic grading with partial rewards
✅ Rewards in range [0.0, 1.0]
✅ 3+ tasks with graders
✅ Docker buildable on port 7860
✅ inference.py at repo root
✅ inference.py uses OpenAI client
✅ inference.py emits [START]/[STEP]/[END] logs
✅ pyproject.toml with server entry point
✅ uv.lock file present
✅ openenv.yaml specification
✅ Runtime < 20 minutes


📈 Expected Performance
MetricValueSuccess Rate≥ 80%Average Reward≥ 0.8Risk LevelLOWConfidence≥ 90%

🔒 Security Scenarios Covered
ScenarioDifficultyThreat TypeData Leakage PreventionEasydata_exfiltrationBrute Force DetectionMediumbrute_forceAdvanced Intrusion ResponseHardintrusion

📄 License
MIT License — see LICENSE for details.
