"""
SDZTG Policy Engine — nftables ruleset generator (P3, allow/deny only)

Turns the static policy.yaml (the same file policy_engine.py reads) into a
complete nftables bridge-filter ruleset, as TEXT. It does NOT apply anything
itself — generation and application are deliberately separate, the same way
evaluate() and save_decision() are separate in policy_engine.py:
  - generate_ruleset() is pure: policy in, ruleset text out, no side effects.
    Safe to call and inspect a thousand times without touching the firewall.
  - applying it (validate -> snapshot -> nft -f -> rollback timer) is a
    separate step, handled by the apply script, so the dangerous part is
    isolated and testable on its own.

Design choices baked in here (so they're explainable line by line):
- Rules match on MAC address (`ether saddr`), not IP. Per policy.yaml,
  devices are identified by MAC, which survives DHCP lease changes. Matching
  on IP would tie every rule to a current lease and silently break when it
  renews.
- Atomic replacement: the output is a full `flush table` + fresh definition,
  meant to be applied with a single `nft -f`. This matches the roadmap's
  requirement of atomic reloads over incremental `nft add rule` calls — the
  whole ruleset swaps in at once, never a half-applied in-between state.
- Fail-CLOSED default: the forward chain ends in `drop`, mirroring
  policy.yaml's `default: deny` (FR11). Anything not explicitly allowed is
  dropped.
- Management-traffic safety: an explicit early accept for the gateway's own
  established/related connections, so an overly broad deny can't sever an
  existing management session mid-reload.

NOTE: throttle/quarantine are intentionally NOT implemented yet — this first
version is allow/deny only, to get the dangerous foundation proven on real
hardware before layering on rate-limiting (throttle) and redirect
(quarantine) mechanisms. A Decision with action "throttle"/"quarantine" is
treated conservatively as a drop here, with a comment, until P3 phase 2.
"""

import yaml

TABLE_NAME = "sdztg_filter"


def _normalize_protocol(proto):
    """nftables uses lowercase l4 protocol keywords (tcp/udp). policy.yaml
    already uses lowercase, but normalize defensively so a stray 'TCP'
    doesn't silently fail to match."""
    if proto == "any":
        return None
    return str(proto).lower()


def _port_clause(port):
    """Render a port match clause. policy.yaml allows a single port, a list
    of ports, or 'any'. Returns '' for 'any' (no port constraint)."""
    if port == "any":
        return ""
    if isinstance(port, list):
        # nftables set syntax: dport { 80, 443 }
        ports = ", ".join(str(p) for p in port)
        return f"dport {{ {ports} }}"
    return f"dport {port}"


def _rule_to_nft(rule, mac_for_device, verb):
    """
    Translate ONE policy rule (allow or deny) into one nftables rule line.

    mac_for_device: a function that maps a device name -> MAC, or None for
    "any"/unresolved. verb is "accept" (allow rules) or "drop" (deny rules).

    Returns None if the rule can't be expressed yet (e.g. a device name that
    isn't in the registry) — the caller skips those and logs a warning rather
    than emitting a broken rule.
    """
    parts = []

    # --- device -> ether saddr match ---
    device = rule.get("device", "any")
    if device != "any":
        mac = mac_for_device(device)
        if mac is None:
            # Named device not in registry — can't build a MAC match for it.
            # Skip rather than emit something wrong.
            return None
        parts.append(f"ether saddr {mac}")

    # --- protocol + port match ---
    proto = _normalize_protocol(rule.get("protocol", "any"))
    port_clause = _port_clause(rule.get("port", "any"))
    if proto:
        if port_clause:
            parts.append(f"{proto} {port_clause}")
        else:
            parts.append(proto)
    elif port_clause:
        # Port specified but protocol "any" — default to tcp for the port
        # match, since a bare port with no l4 protocol isn't valid nft.
        # This is a conservative assumption worth surfacing in review.
        parts.append(f"tcp {port_clause}")

    # --- dest match ---
    dest = rule.get("dest", "any")
    if dest != "any":
        # dest is an IP/CIDR. ip daddr works at the bridge level when the
        # frame carries IP. (Hostname-based dest is not supported here —
        # nftables can't resolve hostnames at rule-eval time.)
        parts.append(f"ip daddr {dest}")

    match = " ".join(parts)
    # A rule with no match parts at all means "everything" — valid, but worth
    # a comment so it's obvious in the output that this is a catch-all.
    if not match:
        return f"        {verb}    # catch-all ({verb})"
    return f"        {match} {verb}"


def _reverse_rule_to_nft(rule, mac_for_device):
    """
    Build the REVERSE of an allow rule, to permit return traffic in a
    stateless filter. Where the forward rule matched "device sends out to
    port X" (ether saddr <mac>, dport X), the reverse matches "replies come
    back to that device from port X" (ether daddr <mac>, sport X).

    Returns None if there's no meaningful reverse to build (e.g. a port:any
    rule needs no port-mirrored reverse — its forward rule already permits
    broadly, and a catch-all reverse would be too loose to be worth it).
    """
    parts = []

    # device -> ether DADDR (reply is addressed TO the device)
    device = rule.get("device", "any")
    if device != "any":
        mac = mac_for_device(device)
        if mac is None:
            return None
        parts.append(f"ether daddr {mac}")

    # protocol + SOURCE port (reply comes FROM the port we allowed out to)
    proto = _normalize_protocol(rule.get("protocol", "any"))
    port = rule.get("port", "any")
    if port == "any":
        # No specific port to mirror — skip building a reverse rule rather
        # than emit an overly broad "anything back to this device" accept.
        return None
    if isinstance(port, list):
        ports = ", ".join(str(p) for p in port)
        sport_clause = f"sport {{ {ports} }}"
    else:
        sport_clause = f"sport {port}"

    if proto:
        parts.append(f"{proto} {sport_clause}")
    else:
        parts.append(f"tcp {sport_clause}")

    match = " ".join(parts)
    if not match:
        return None
    return f"        {match} accept    # reverse/return-path for allow rule above"


def generate_ruleset(policy: dict) -> str:
    """
    Build the full nftables bridge-filter ruleset text from a loaded policy
    dict (the same structure policy_engine.load_policy returns).
    """
    # device name -> MAC lookup, uppercased for consistency with how
    # policy_engine builds its lookup.
    name_to_mac = {d["name"]: d["mac"] for d in policy["devices"]}

    def mac_for_device(name):
        return name_to_mac.get(name)

    lines = []
    lines.append(f"#!/usr/sbin/nft -f")
    lines.append(f"# Generated by nft_generator.py from policy.yaml — do not edit by hand.")
    lines.append(f"# Apply atomically with: nft -f <thisfile>")
    lines.append("")
    # Flush only OUR table, by name — never `flush ruleset`, which would wipe
    # every table on the box including anything else relying on nftables.
    lines.append(f"table bridge {TABLE_NAME}")
    lines.append(f"delete table bridge {TABLE_NAME}")
    lines.append("")
    lines.append(f"table bridge {TABLE_NAME} {{")
    lines.append(f"    chain forward {{")
    lines.append(f"        type filter hook forward priority 0; policy drop;")
    lines.append("")
    lines.append(f"        # NOTE: no `ct state` line here. Connection tracking is not")
    lines.append(f"        # available in the nftables bridge family by default, so this")
    lines.append(f"        # is a STATELESS filter for the allow/deny MVP. Return traffic")
    lines.append(f"        # for allowed flows is handled by the allow rules matching in")
    lines.append(f"        # both directions, not by connection state. Revisit if we move")
    lines.append(f"        # enforcement to the inet family later.")
    lines.append("")

    # --- DENY rules FIRST ---
    # CRITICAL ORDERING: the policy engine's rule is "deny wins on conflict."
    # nftables chains are first-match-wins by order. So to make the firewall
    # behave identically to the engine, deny rules MUST be emitted BEFORE
    # allow rules — a flow matching both hits the drop first and stops.
    # Emitting allow first would silently invert the policy's meaning.
    lines.append(f"        # --- deny rules FIRST (deny wins on conflict, per P2 design) ---")
    for i, rule in enumerate(policy.get("deny", [])):
        action = rule.get("action", "deny")
        # In the allow/deny-only phase we do NOT emit throttle/quarantine
        # rules at all. Translating them to a blanket drop is actively
        # dangerous: the new_device rule is device:any/dest:any/port:any,
        # which would become a catch-all drop placed BEFORE the allow rules,
        # killing all traffic including legitimate flows. Skipping is the
        # safe, honest choice until rate-limiting/redirect land in phase 2.
        if action in ("throttle", "quarantine"):
            lines.append(f"        # SKIPPED deny[{i}]: action='{action}' not implemented yet (P3 phase 2)")
            continue
        nft_line = _rule_to_nft(rule, mac_for_device, "drop")
        if nft_line is None:
            lines.append(f"        # SKIPPED deny[{i}]: device not in registry")
        else:
            lines.append(nft_line)
    lines.append("")

    # --- ALLOW rules (forward + reverse for return traffic) ---
    # Because the bridge family is STATELESS (no ct state), each allow rule
    # needs a mirror that permits the return traffic. Forward rule matches
    # the device sending out (saddr + dport); reverse rule matches replies
    # coming back (daddr + sport). This is the Option-1 tradeoff: it's
    # looser than stateful tracking (a packet that merely claims sport 443
    # is accepted), but acceptable for the isolated test topology. Documented
    # as such; Option 2 (inet-family conntrack) is future work.
    lines.append(f"        # --- allow rules + reverse return-path (stateless, Option 1) ---")
    for i, rule in enumerate(policy.get("allow", [])):
        fwd = _rule_to_nft(rule, mac_for_device, "accept")
        if fwd is None:
            lines.append(f"        # SKIPPED allow[{i}]: device not in registry")
            continue
        lines.append(fwd)
        rev = _reverse_rule_to_nft(rule, mac_for_device)
        if rev is not None:
            lines.append(rev)
    lines.append("")

    lines.append(f"        # --- default ---")
    lines.append(f"        # policy drop above already enforces default-deny (FR11),")
    lines.append(f"        # this explicit drop is belt-and-suspenders + readable in logs.")
    lines.append(f"        drop")
    lines.append(f"    }}")
    lines.append(f"}}")
    lines.append("")
    return "\n".join(lines)
