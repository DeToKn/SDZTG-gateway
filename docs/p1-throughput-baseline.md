# P1 — Throughput & Latency Baseline (Pre-Filtering)

**Date:** 2026-06-23
**Roadmap item:** P1 — "Baseline throughput before any filtering" (per `ztpnp-roadmap.jsx`)
**Purpose:** Establish a "before" control number across `br0` before any nftables
rules exist. Once P3 adds enforcement, these numbers are what filtered
throughput gets compared against — without this baseline, any slowdown
observed later would be impossible to attribute to the policy engine vs.
hardware limits that were already there.

## Methodology

Tool: `iperf3` (TCP, default settings, 10-second test windows).
Three machines involved:
- **Gateway** (`2019Deezo`) — `br0` IP `192.168.1.174` (see note below on `enp1s0`'s
  stale address)
- **Laptop** (victim/test device) — wired into `enxa0cec8b67eda`, DHCP lease
  `192.168.1.177`, Wi-Fi disabled throughout testing
- **Windows dev PC** — `192.168.1.142` on the same LAN, also reachable via
  Tailscale (`100.105.167.86`)

For each pair, both directions were tested (`iperf3 -c <host>` and
`iperf3 -c <host> -R`) since USB NICs and VPN tunnels are known to behave
asymmetrically — testing only one direction would have missed that.

## Results

| Path | Forward | Reverse | Notes |
|---|---|---|---|
| Gateway ↔ Laptop (`enxa0cec8b67eda`, USB NIC) | 782 Mbits/s | 946 Mbits/s | Downstream/victim-side NIC |
| Gateway ↔ Windows PC (Tailscale) | 898 Mbits/s | 603 Mbits/s | Management-plane path, WireGuard overhead |
| Windows PC ↔ Laptop (full end-to-end through `br0`) | 922 Mbits/s | 770 Mbits/s | Closest approximation of real device traffic |

All results well under the 1 Gbps theoretical ceiling, as expected — none
of these paths are pure onboard-Gigabit-to-onboard-Gigabit.

## Findings

**USB NIC asymmetry (Gateway ↔ Laptop):** Sending *into* the USB NIC
(laptop → gateway) was ~17% slower than receiving from it (gateway →
laptop). Consistent with known USB-Ethernet adapter behavior — outbound
framing through a USB controller costs more than inbound. This matches
what `architecture.md` already predicted: the USB NIC is explicitly
flagged as scope-limited, not production-grade. This test gives that
claim a real number instead of leaving it as a guess.

**Tailscale overhead (Gateway ↔ Windows PC):** Asymmetry here was larger
and in the *opposite* direction — gateway sending to Windows PC was
notably slower (603 Mbits/s) than Windows PC sending to the gateway (898
Mbits/s). Likely WireGuard encryption/decryption cost rather than NIC
hardware, since this path doesn't touch `enxa0cec8b67eda` at all. This is
a management-plane number, not part of the data-plane filtering
comparison — kept here for completeness, not as a P3 baseline.

**End-to-end (Windows PC ↔ Laptop) was the strongest overall result** —
both directions in the 770–922 Mbits/s range despite crossing both NICs
and the full bridge. This is the number most representative of real
device traffic and the one P3's filtered numbers should be compared
against most directly.

## Known issue encountered during testing

A direct `ping` between the Windows PC and the gateway/laptop failed or
returned "destination host unreachable" even though `iperf3` (TCP)
succeeded cleanly between the same hosts. Root causes identified:

- `192.168.1.218` (the gateway's *former* `enp1s0` address, from before
  the bridge was built) is stale — `enp1s0` lost its standalone IP once
  it became a bridge port, and `br0` now holds `192.168.1.174` instead.
  Pinging `.218` correctly returns "unreachable" because nothing claims
  that address anymore. **Action item:** update any remaining references
  to `192.168.1.218` in scripts/docs to `192.168.1.174`.
- ICMP (ping) appears to be blocked by Windows Firewall on at least one
  host, while TCP (`iperf3`) was not. This is a known default-Windows
  behavior, not a bridge/gateway problem — confirmed by `iperf3` working
  normally on the same paths where `ping` failed.

## What's still open

- Latency (`ping`/`mtr`-style RTT measurements) was not formally captured
  this session due to the ICMP-blocking issue above. Throughput is
  recorded; round-trip latency baseline is still a documentation gap if
  the project wants that figure for Chapter 4.
- These are single-run figures per path/direction, not averaged across
  multiple runs. Acceptable for a baseline reference point; worth
  re-running 2–3 times each if a more statistically solid number is
  wanted for the final eval writeup (E2 in the roadmap).
