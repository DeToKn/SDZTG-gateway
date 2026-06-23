# Session Log — 2026-06-23 — Bringing Up `br0`

**Phase:** Policy Engine + Inline Enforcement (P0)
**Goal for the session:** Build the `br0` bridge to make the gateway actually inline, and confirm both NICs (`enp1s0`, `enxa0cec8b67eda`) were genuinely ready to be bridged.

## What went wrong first

While building the bridge, my Tailscale connection dropped from my Windows machine, and right after that my home Wi-Fi started acting up too — both happening right after I enslaved the second NIC (`enxa0cec8b67eda`) to `br0`.

## Root cause

The Wi-Fi disruption happened because both NICs were plugged into the same TP-Link router/switch. Bridging two ports of the same network together created a loop — frames had more than one path between the same two points, and with no spanning-tree delay in place yet, it flooded the LAN. That's also what knocked Tailscale's underlying transport out from under it, since the management traffic was riding the same physical NIC that just got enslaved.

## What got me back on track

1. **Going physically to the Dell** and realizing the two NICs could not both stay connected to the TP-Link — one had to go to a genuinely separate, downstream-only device for the bridge to make sense as an inline firewall instead of a loop.
2. **Realizing the Pi Zero 2 W had no Ethernet port** — it's Wi-Fi only, so it couldn't be the wired test device I needed. My old laptop had a built-in Ethernet port, so it became the new victim/test device, cabled directly into `enxa0cec8b67eda`.
3. **Finding the conflicting netplan files** — `01-network-manager-all.yaml` (telling the system to use NetworkManager for everything) and `50-cloud-init.yaml` (DHCP'ing `enp1s0` directly) were both still active and disagreeing with the bridge config I was trying to apply. Disabled cloud-init's network management and moved both old files aside before the new bridge config could be trusted to apply cleanly.

## The actual attempt

With a person physically at the gateway in case anything needed a cable pulled or a power cycle, I ran the bridge config from work over SSH/Tailscale. `netplan try` initially refused to even attempt the change — it said reverting custom bridge parameters (`stp`, `forward-delay`) wasn't supported, so I stripped those out and tried again with a simpler config.

## The win

I was away from home at work when I ran the actual NIC enslavement, and the SSH session **did not drop** — it connected successfully right through the change. If it hadn't worked, I would've had to wait until I got off work to go reset everything in person. The `netplan try` refusal earlier was genuinely worrying too, because at that point it felt like all-or-nothing — no safety net if the real attempt went wrong.

Confirmed afterward: both NICs (`enp1s0`, `enxa0cec8b67eda`) show as `master br0, state forwarding`, `br0` holds the DHCP lease, and the config is persisted in `/etc/netplan/01-sdztg-br0.yaml` so it survives a reboot.

## What's still open

- Confirm the laptop actually pulls a DHCP lease and reaches the internet through `br0` (laptop was asleep at time of writing — needs a physical check).
- Add the STP/forward-delay parameters back in a separate, lower-stakes pass now that the basic bridge is proven stable.

## Lessons for next time

- **Physical topology matters as much as the config.** No amount of `ip link` or netplan tuning fixes a wiring mistake — the two NICs had to actually face two different networks before the software side made sense.
- **Always have a recovery plan before touching network changes that could lock you out** — having someone physically at the machine, ready to pull a cable or power-cycle, was the difference between "recoverable experiment" and "stranded until end of work shift."
- **Don't trust a tool's status message blindly — verify yourself.** `netplan try` printed "Reverting" at one point, but the live bridge state (`bridge link`, `ip addr show`) showed both NICs were still enslaved and working. The tool's own bookkeeping was wrong; the actual kernel state was the ground truth.
