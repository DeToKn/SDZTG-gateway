"""
Example: how to use init_decisions_table() and save_decision() for real.
This is a demo script, NOT something to paste line-by-line into bash —
run the whole file at once with: python3 example_usage.py
"""

import sys
import os

# Adjust this if your repo layout differs — this assumes the script
# sits in the repo root, next to src/ and tests/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from policy_engine import (
    Flow,
    load_policy,
    build_device_lookup,
    evaluate,
    init_decisions_table,
    save_decision,
)

# --- one-time setup ---
DB_PATH = "/home/devinlinux/sdztg-gateway/data/packets.db"
POLICY_PATH = "/home/devinlinux/sdztg-gateway/src/policy.yaml"

policy = load_policy(POLICY_PATH)
device_lookup = build_device_lookup(policy)
init_decisions_table(DB_PATH)  # safe to call every run, idempotent

# --- example: evaluate one flow and log the decision ---
flow = Flow(
    src_mac="20:47:47:50:e2:e5",
    dest="93.184.216.34",
    port=443,
    protocol="tcp",
)
decision = evaluate(flow, policy, device_lookup)
save_decision(flow, decision, DB_PATH)

print(f"Logged decision: {decision.action} ({decision.matched_rule})")
print(f"Reason: {decision.reason}")
