# Lab Environment

## Gateway Machine (Linux)

| Field | Value |
|-------|-------|
| Hostname | 2019Deezo |
| OS | Ubuntu 24.04.4 LTS (Noble) |
| CPU cores | 4 |
| RAM | 15 GB total / 11 GB available |
| Swap | 4 GB |
| IP Address | 192.168.1.218 |

## Network Interfaces

| Interface | MAC | State | Role |
|-----------|-----|-------|------|
| lo | 00:00:00:00:00:00 | LOOPBACK | Loopback |
| enp1s0 | 6c:2b:59:fb:75:00 | UP | Primary NIC (upstream) |

## Test Device

| Field | Value |
|-------|-------|
| Hardware | Raspberry Pi Zero 2 W |
| Role | Victim / IoT test device |
| Connection | Downstream via gateway bridge |

## Topology

## Reproducibility Notes

- Python: 3.12 (system), virtualenv at `.venv/`
- Gateway NIC: enp1s0 (onboard Gigabit)
- Second NIC needed for full bridge — USB Gigabit adapter (to be added)
- All commands run as user: devinlinux