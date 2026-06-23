"""
SDZTG Policy Engine — flow evaluator (P2)

This module answers ONE question: given a flow (who's talking, to where,
on what port/protocol) and a loaded policy file, what should happen to it?

Design intent (so this is easy to explain later, line by line):
- One flow in, one Decision out. No batching — this mirrors how capture.py
  already processes packets one at a time in TAD, so wiring this in later
  (P3) is a single function call inside the existing loop, not a rewrite.
- Evaluation order is fixed and deliberate: ALLOW rules checked first, then
  DENY rules, then DEFAULT. But DENY always wins if both an allow and a
  deny rule match the same flow. This is the "zero-trust" choice: when two
  rules disagree, fail closed (block), not open (allow).
- Every Decision carries exactly ONE reason — the single rule that decided
  it (or "default" if nothing matched). The priority order above is what
  guarantees there's never a genuine tie needing more than one reason.
"""

from dataclasses import dataclass
from typing import Optional
import yaml


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    """
    One flow to be evaluated. This is intentionally a thin, plain structure —
    capture.py is what will eventually construct one of these per real
    packet/connection. The policy engine doesn't care where the data came
    from, only what it contains.
    """
    src_mac: str        # e.g. "AA:BB:CC:DD:EE:FF" — who's sending traffic
    dest: str            # destination IP/hostname, or "any" isn't valid here —
                          # a real flow always has a real destination.
    port: int
    protocol: str        # "tcp" | "udp" | "icmp"


@dataclass
class Decision:
    """
    The output of evaluate(). Exactly one action, exactly one reason.
    This is what gets written to the SQLite `decisions` table later (P2
    checklist item) — one row per flow, no ambiguity about why.
    """
    action: str          # "allow" | "deny" | "throttle"
    matched_rule: str    # human-readable id of which rule decided this,
                          # e.g. "allow[1]", "deny[0]", or "default"
    reason: str          # pulled from the rule's `notes` field, or a
                          # generic explanation if the rule had none


# ---------------------------------------------------------------------------
# Loading + validating the policy file
# ---------------------------------------------------------------------------

def load_policy(path: str) -> dict:
    """
    Read the YAML file and do the minimum sanity-checking needed before we
    trust it to make security decisions. We are deliberately strict here:
    a malformed policy file should fail loudly at startup, not silently
    produce wrong decisions at runtime.
    """
    with open(path, "r") as f:
        policy = yaml.safe_load(f)

    required_keys = ("devices", "allow", "deny", "default")
    for key in required_keys:
        if key not in policy:
            raise ValueError(f"Policy file is missing required key: '{key}'")

    # This is the one rule we never let slide, per FR11 (default-deny).
    # If someone edits the YAML and flips this to "allow", we want the
    # program to refuse to run rather than silently become permissive.
    if policy["default"] != "deny":
        raise ValueError(
            f"Policy 'default' must be 'deny', got '{policy['default']}'. "
            "Refusing to load an unsafe default policy."
        )

    return policy


def build_device_lookup(policy: dict) -> dict:
    """
    Turn the devices: list into a dict keyed by MAC address (uppercase, so
    comparisons aren't broken by case differences like 'aa:bb' vs 'AA:BB').
    This gives us O(1) "what device is this MAC?" lookups instead of
    scanning the list every time we evaluate a flow.
    """
    lookup = {}
    for device in policy["devices"]:
        mac = device["mac"].upper()
        lookup[mac] = device["name"]
    return lookup


# ---------------------------------------------------------------------------
# Matching a single rule against a single flow
# ---------------------------------------------------------------------------

def _device_matches(rule_device, flow_device_name: Optional[str]) -> bool:
    """
    rule_device can be: "any", a single device name, or a list of names.
    flow_device_name is None if the flow's MAC wasn't found in the registry
    (i.e. this is an unregistered/new device).
    """
    if rule_device == "any":
        return True
    if flow_device_name is None:
        # An unregistered device can only ever match an "any" rule —
        # it can't match a rule written for a specific named device,
        # because by definition we don't know its name yet.
        return False
    if isinstance(rule_device, list):
        return flow_device_name in rule_device
    return rule_device == flow_device_name


def _field_matches(rule_value, flow_value) -> bool:
    """
    Shared logic for dest/port/protocol matching. "any" always matches.
    A list means "matches if flow_value is one of these" (used for the
    port: [23, 21] style rules in the schema).
    """
    if rule_value == "any":
        return True
    if isinstance(rule_value, list):
        return flow_value in rule_value
    return rule_value == flow_value


def _condition_matches(rule: dict, flow_device_name: Optional[str]) -> bool:
    """
    Handles the optional `condition:` field. This is separate from the
    device/dest/port/protocol fields because it's not about the flow's
    contents — it's about the flow's CONTEXT (is this device known to us
    at all?). Right now we only support one condition, but this function
    is the single place to add more later instead of scattering special
    cases through _rule_matches.

    BUG FIX (caught by the test harness): a rule with no `condition` key
    at all must always pass this check — otherwise rules that don't use
    conditions would never match anything. Only a rule that explicitly
    sets condition: "new_device" gets the extra restriction.
    """
    condition = rule.get("condition")
    if condition is None:
        return True
    if condition == "new_device":
        # "New" means we couldn't resolve this MAC to a name in the
        # registry at all — flow_device_name is None in that case.
        return flow_device_name is None
    # Unknown condition string — fail safe by not matching, rather than
    # guessing. A typo in the YAML should never silently grant a match.
    return False


def _rule_matches(rule: dict, flow: Flow, flow_device_name: Optional[str]) -> bool:
    """
    A rule matches a flow only if EVERY field matches. This is a plain AND
    across device/dest/port/protocol/condition — there's no partial-credit
    matching.
    """
    return (
        _device_matches(rule.get("device", "any"), flow_device_name)
        and _field_matches(rule.get("dest", "any"), flow.dest)
        and _field_matches(rule.get("port", "any"), flow.port)
        and _field_matches(rule.get("protocol", "any"), flow.protocol)
        and _condition_matches(rule, flow_device_name)
    )


def _reason_for(rule: dict, fallback: str) -> str:
    """Pull the human-readable explanation straight from the YAML's notes
    field, falling back to a generic message if the rule author didn't
    write one. Keeps the 'why' in the decision log traceable back to the
    exact comment a human wrote when they created the rule."""
    return rule.get("notes", fallback)


# ---------------------------------------------------------------------------
# The actual evaluator
# ---------------------------------------------------------------------------

def evaluate(flow: Flow, policy: dict, device_lookup: dict) -> Decision:
    """
    Evaluate one flow against the loaded policy.

    Order of operations (this IS the security model, not just code style):
      1. Resolve the flow's source MAC to a device name (or None if unknown).
      2. Check every DENY rule. If ANY matches, return deny immediately —
         deny always wins, we don't even bother checking allow at this point.
      3. Check every ALLOW rule. First match wins.
      4. Nothing matched -> fall through to the policy's default (deny).
    """
    flow_device_name = device_lookup.get(flow.src_mac.upper())

    # Step 2: deny checked FIRST in the code, even though conceptually we
    # describe it as "allow checked first, deny wins on conflict" — the
    # *outcome* is identical either way (deny always wins), but checking
    # deny first in the implementation means we never do wasted work
    # evaluating allow rules for a flow that's going to be denied regardless.
    for i, rule in enumerate(policy["deny"]):
        if _rule_matches(rule, flow, flow_device_name):
            action = rule.get("action", "deny")  # supports deny/throttle/quarantine
            return Decision(
                action=action,
                matched_rule=f"deny[{i}]",
                reason=_reason_for(rule, "Matched a deny rule"),
            )

    # Step 3: no deny matched, now check allow.
    for i, rule in enumerate(policy["allow"]):
        if _rule_matches(rule, flow, flow_device_name):
            return Decision(
                action="allow",
                matched_rule=f"allow[{i}]",
                reason=_reason_for(rule, "Matched an allow rule"),
            )

    # Step 4: nothing matched at all. Fall through to default-deny.
    return Decision(
        action=policy["default"],
        matched_rule="default",
        reason="No allow or deny rule matched; default-deny applied (FR11)",
    )
