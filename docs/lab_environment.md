# Lab Environment

> Canonical hardware / network inventory for the SDZTG project.
> **Last updated:** after adding the USB Gigabit adapter — `enxa0cec8b67eda` is now present and `br0` is buildable.

---

## Gateway Machine (Linux)

| Field      | Value                                      |
| ---------- | ------------------------------------------ |
| Hostname   | `2019Deezo`                                |
| OS         | Ubuntu 24.04.4 LTS (Noble)                 |
| CPU cores  | 4                                          |
| RAM        | 15 GB total / 11 GB available              |
| Swap       | 4 GB                                       |
| IP Address | 192.168.1.218 (management, via `tailscale0` overlay) |

---

## Network Interfaces

| Interface       | MAC               | State | Role                                                              |
| --------------- | ----------------- | ----- | ----------------------------------------------------------------- |
| `lo`            | `00:00:00:00:00:00` | LOOPBACK | Loopback                                                      |
| `enp1s0`        | `6c:2b:59:fb:75:00` | UP       | Onboard NIC — **bridge member**, upstream (WAN) side of `br0`    |
| `enxa0cec8b67eda` | `a0:ce:c8:b6:7e:da` | UP       | USB-3 Gigabit (RTL8153) — **bridge member**, downstream IoT side of `br0` |
| `tailscale0`    | (none, TUN)       | UP     | **Management plane only.** Out-of-band from `br0`. Carries SSH, dashboard, Git pulls from Windows dev box. Never carries IoT traffic. |

> **Plane separation** (see `docs/architecture.md` §2):
> - `br0` = data plane (IoT traffic, inline-enforced)
> - `tailscale0` = management plane (you SSH in from here)
> - Code sync happens over GitHub, not over `br0` or `tailscale0`

---

## Test Device

| Field     | Value                                              |
| --------- | -------------------------------------------------- |
| Hardware  | Raspberry Pi Zero 2 W                               |
| Role      | Victim / IoT test device                          |
| Connection| Downstream of `br0`, reached via `enxa0cec8b67eda` |
| Typical IP| `192.168.1.x` (DHCP from upstream router, unchanged by the bridge — that's the whole point of L2 transparency) |

---

## Topology

```
                              [Router / Internet]
                                       │
                            enp1s0 (onboard NIC)
                                       │
   ┌─────────────────── Dell OptiPlex 3060 ────────────────────┐
   │                                                         │
   │                  br0 (Layer-2 bridge)                   │
   │             enp1s0  ──────── br0 ────────  enxa0cec8b67eda│
   │                                                         │
   │   tailscale0 ◄─── mgmt plane (out-of-band)             │
   └─────────────────────────────────────────────────────────┘
                                       │
                            enxa0cec8b67eda (USB NIC)
                                       │
                              [Pi Zero 2 W]
                              (victim device)
```

---

## Reproducibility Notes

- **Python:** 3.12 (system), virtualenv at `.venv/`
- **Gateway NICs:** both bridge members present — `enp1s0` (onboard) and `enxa0cec8b67eda` (USB-3 Gigabit)
- **Management plane:** Tailscale daemon on this host + on the Windows dev box; SSH over `100.x.y.w` (this host's Tailscale IP)
- **Code flow:** Windows (Cursor / VS Code) → `git push` → GitHub → `git pull` on `2019Deezo` over Tailscale SSH
- **All commands run as user:** `devinlinux` (sudo via `sudo -E` for nftables / sysctl / netplan)

---

## Change Log

| Date       | Change                                                          |
| ---------- | --------------------------------------------------------------- |
| 2026-06-23 | Added `enxa0cec8b67eda` (USB Gigabit) — `br0` now buildable. Updated interface table to include `tailscale0` and document plane separation. Previous version of this doc incorrectly listed only `enp1s0`. |
