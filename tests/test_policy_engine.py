"""
Quick manual test harness for policy_engine.py — NOT a formal test suite
(no pytest yet), just a readable script you can run and reason through
line by line. Each test prints what flow we're checking, what we expected,
and what we got, so a mismatch is obvious immediately.

Run from the repo root with:  python tests/test_policy_engine.py
"""

import sys
import os

# This test lives in tests/, but policy_engine.py lives in src/. We add
# the src/ directory to the import path so `from policy_engine import ...`
# resolves. os.path.dirname(__file__) is the tests/ folder; '..' goes up
# to the repo root; then into 'src'. This mirrors the sys.path pattern
# used elsewhere in the project, just pointed at src/ instead of the
# test's own folder.
SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)

from policy_engine import Flow, load_policy, build_device_lookup, evaluate

# policy.yaml lives in src/ alongside policy_engine.py, so build an
# absolute path to it rather than assuming the current working directory.
POLICY_PATH = os.path.join(SRC_DIR, "policy.yaml")

policy = load_policy(POLICY_PATH)
device_lookup = build_device_lookup(policy)

print("Device lookup table:", device_lookup)
print()

# The laptop's real MAC, confirmed once it was awake and wired into
# enxa0cec8b67eda (DHCP lease .177). This must match the mac registered
# in policy.yaml — if they drift apart, the laptop reads as an unknown
# device and gets throttled instead of allowed.
LAPTOP_MAC = "20:47:47:50:e2:e5"
UNKNOWN_MAC = "DE:AD:BE:EF:00:01"  # not in the registry at all


test_cases = [
    # (description, flow, expected_action)
    (
        "Laptop browsing HTTPS — should be allowed",
        Flow(src_mac=LAPTOP_MAC, dest="93.184.216.34", port=443, protocol="tcp"),
        "allow",
    ),
    (
        "Laptop trying telnet (port 23) — should be denied, even though it's allowed to browse",
        Flow(src_mac=LAPTOP_MAC, dest="93.184.216.34", port=23, protocol="tcp"),
        "deny",
    ),
    (
        "Laptop reaching the router for DHCP/management — should be allowed (the 'any' device rule)",
        Flow(src_mac=LAPTOP_MAC, dest="192.168.1.1", port=53, protocol="udp"),
        "allow",
    ),
    (
        "Laptop trying some random unlisted port to a random host — should fall to default-deny",
        Flow(src_mac=LAPTOP_MAC, dest="8.8.8.8", port=9999, protocol="tcp"),
        "deny",
    ),
    (
        "A device we've never seen before, trying anything — should get throttled (plug-and-play safety net)",
        Flow(src_mac=UNKNOWN_MAC, dest="1.1.1.1", port=80, protocol="tcp"),
        "throttle",
    ),
]

all_passed = True
for description, flow, expected in test_cases:
    decision = evaluate(flow, policy, device_lookup)
    passed = decision.action == expected
    all_passed = all_passed and passed
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {description}")
    print(f"        flow: {flow}")
    print(f"        decision: action={decision.action} rule={decision.matched_rule}")
    print(f"        reason: {decision.reason}")
    if not passed:
        print(f"        >>> EXPECTED {expected}, GOT {decision.action}")
    print()

print("=" * 60)
print("ALL TESTS PASSED" if all_passed else "SOME TESTS FAILED — see above")
