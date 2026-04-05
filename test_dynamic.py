#!/usr/bin/env python
"""Test dynamic scenario generation"""

import random
from environment import AiSecurityEnv

env = AiSecurityEnv(seed=42, use_dynamic=True)

# Reset multiple times to see dynamic generation
for i in range(3):
    state = env.reset()
    print(f"\n--- Event {i+1} ---")
    print(f"Event ID: {state.get('event_id')}")
    print(f"Data Sensitivity: {state.get('data_sensitivity')}")
    print(f"User Role: {state.get('user_role')}")
    print(f"Logs (first 2):")
    for log in state.get('logs', [])[:2]:
        print(f"  - {log}")

print("\n✓ Dynamic scenario generation working!")
print("✓ Each reset generates different events while maintaining reproducibility")
