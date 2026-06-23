Security Notes & Known Limitations

Project: Software-Defined Zero-Trust Gateway (SDZTG)
Last updated: Phase 6 complete, Tailscale remote access configured


1. Management Interface (dashboard.py)

Current State


Dashboard is read-only — displays data only, no enforcement controls
Runs on Flask + Flask-SocketIO, accessible at http://192.168.1.218:5000 (local)
No authentication required to view dashboard
WebSocket connection accepts unauthenticated clients (auth=None)


Why This Is Acceptable Now


Local network only, not internet-exposed
Read-only interface — cannot issue commands or change policy
Prototype phase — NFR9 compliance is a Phase 2 requirement, not yet due


Required Before Enforcement Controls Are Added (Phase 2 / Policy Engine)


Login page — username + password before dashboard access
Session tokens — Flask-Login or JWT-based session management
HTTPS/TLS — encrypt management traffic (NFR9)
WebSocket auth — validate token in on_connect() before accepting connection
Rate limiting — prevent brute force on login endpoint


How To Talk About This (Defense + Interview)


"The current dashboard is read-only and local-network only. Authentication
is a documented requirement under NFR9 and will be implemented before
enforcement controls are exposed through the interface. This is a
deliberate, documented trade-off for the prototype stage — not an oversight."



NFR Reference


NFR7: Gateway hardening
NFR8: Secure credential storage
NFR9: Secure management communication (HTTPS/TLS + SSH)
NFR10: Tamper-evident audit storage



2. Database (SQLite)


DB_PATH is hardcoded to /home/devinlinux/sdztg-gateway/data/packets.db
Acceptable for single-user prototype; should move to a config file or
environment variable before any multi-user or production deployment
WAL (Write-Ahead Logging) journal mode enabled for concurrent read/write
performance — required once dashboard, capture, and alerts all hit the
DB simultaneously
No encryption at rest currently — packet data and DNS query history are
stored in plaintext SQLite. Acceptable for lab use; would need encryption
for any data containing real user traffic outside a controlled lab.



3. Packet Capture (capture.py / dns_detect.py)


Requires sudo for raw socket access (Scapy needs CAP_NET_RAW)
Known risk: running the entire capture process as root is broader
privilege than necessary
Planned fix (not yet implemented): grant the capability directly to
the Python binary instead of running the whole process as root:


bash  sudo setcap cap_net_raw+ep .venv/bin/python3

This has NOT been applied yet — capture currently still runs via sudo.


4. Credentials (.env)


Telegram bot token and chat ID stored in .env, excluded from git via
.gitignore
Loaded via python-dotenv at runtime
.env exists independently on both the Windows dev machine and the
Linux gateway — not synced through git (correct, intentional)
Risk: .env is plaintext on disk. Acceptable for prototype/lab.
Production deployment would need a secrets manager or at minimum
filesystem permissions locked to the owning user only.



5. Remote Access — Tailscale Mesh

Current Setup


Tailscale installed on: Linux gateway, Windows dev machine
Linux gateway Tailscale IP: 100.105.167.86
Linux gateway tagged tag:gateway in Tailscale ACLs
SSH confirmed working over Tailscale (both CLI and VS Code Remote-SSH)
Local network SSH (192.168.1.218:22) is still active and unrestricted
— this has NOT yet been locked down to Tailscale-only


Tailscale ACL (Access Control)

Current policy restricts external/invited users (autogroup:member) to:


Destination: tag:gateway only
Port: 22 (SSH) only


This means an invited collaborator:


Cannot see or reach the Windows machine
Cannot reach the local 192.168.1.x subnet generally
Cannot reach the Pi-hole (not tagged, not advertised on Tailscale)
Can only SSH into the Linux gateway on port 22


Why a Compromised Collaborator Account Still Can't Move Laterally

Three independent, stacked controls — any one of which would stop this on
its own:


Tailscale ACL — collaborator's device literally cannot route to
anything except tag:gateway:22. The Pi-hole and Windows machine are
invisible to them at the network layer.
Inline bridge (once Policy Engine / Phase 2 is built) — all local
traffic will physically pass through the gateway's nftables rules,
which deny-by-default.
Physical/logical isolation — Pi-hole has no Tailscale presence at
all and sits on a private, non-routable local IP.


Known Gaps / Not Yet Done


 Local network SSH (192.168.1.218:22) has not been restricted to
Tailscale-only via ufw. Currently anyone on the local WiFi could
still attempt to reach SSH directly, bypassing the Tailscale ACL
entirely for an on-premises attacker.
Planned command (not yet run):




bash      sudo ufw enable
      sudo ufw allow in on tailscale0 to any port 22
      sudo ufw deny 22


 SSH password authentication is still enabled. Key-based auth only
has been discussed but not implemented.
 SSH is still on default port 22 on the local interface. A port
change (discussed: 2019) was decided as not necessary since
Tailscale ACL is the real control, but local-network port 22
remains an open scan target until the ufw restriction above is
applied.



6. Pi-hole / DNS

Status: NOT YET OPERATIONAL


Raspberry Pi Zero 2 W designated as dedicated Pi-hole appliance
Headless install in progress (Raspberry Pi OS Lite, SSH + WiFi
pre-configured via Raspberry Pi Imager)
Pi-hole install command identified: curl -sSL https://install.pi-hole.net | bash
Not yet connected to router as network DNS
Not yet added to Tailscale (would need its own Tailscale install to
serve DNS to the mesh while away from home network)
Not yet added to Tailscale DNS settings
(https://login.tailscale.com/admin/dns)


Why This Matters For Security (once built)


Pi-hole will NOT be tagged on Tailscale and will NOT be reachable by
invited collaborators — intentional isolation (see Section 5)
DNS-level filtering can also surface security-relevant telemetry: which
devices on the network are making unusual outbound DNS calls — directly
complementary to the DNS exfiltration detection already built in
dns_detect.py



7. Trust Boundaries Summary

ActorCan ReachCannot ReachProject owner (you)Everything—Invited Tailscale collaboratorLinux gateway, port 22 onlyWindows PC, Pi-hole, local subnet, any other portLocal WiFi device (uninvited)Currently: gateway SSH on 22 (unrestricted)N/A until ufw rule appliedInternet (uninvited)Nothing — no port forwarding configuredEverything


8. Outstanding Action Items (in priority order)


Apply ufw rule restricting local SSH to Tailscale interface only
Move from SSH password auth to key-based auth
Apply setcap cap_net_raw+ep to Python binary so capture doesn't
require full sudo
Complete Pi-hole headless install and connect to router
Add Pi-hole to Tailscale and configure as Tailscale DNS nameserver
Implement dashboard authentication before Policy Engine enforcement
controls are added (see Section 1)
Set up external syslog forwarding so TAD logs are written somewhere
the gateway itself cannot modify (defense-in-depth against a
compromised gateway account)
Set up process monitoring (systemd watchdog or monit) to alert via
Telegram if any TAD process dies unexpectedly or its binary is modified