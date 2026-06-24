#!/bin/bash
# safe_apply_nft.sh — apply an nftables ruleset with an automatic rollback.
#
# This is the `netplan try` equivalent for the firewall. nftables has no
# built-in auto-revert, so we build one: snapshot the current ruleset,
# apply the new one, then a background job restores the snapshot after a
# timeout UNLESS you confirm you're still alive. If a bad rule severs your
# SSH/management path, doing nothing restores connectivity automatically.
#
# Usage:  sudo ./safe_apply_nft.sh /tmp/sdztg.nft
#
# After it applies, you have TIMEOUT seconds to run:  sudo touch /tmp/nft_confirm
# (or just type 'yes' at the prompt if your session survived) to keep the rules.
# If you don't, the old ruleset is restored automatically.

set -euo pipefail

NEW_RULES="${1:?Usage: sudo ./safe_apply_nft.sh <ruleset-file>}"
TIMEOUT=60
SNAPSHOT="/tmp/nft_snapshot_$(date +%s).nft"
CONFIRM_FLAG="/tmp/nft_confirm"

if [[ $EUID -ne 0 ]]; then
  echo "Must run as root (sudo)." >&2
  exit 1
fi

echo "[1/5] Validating new ruleset syntax (applies nothing)..."
if ! nft -c -f "$NEW_RULES"; then
  echo "    SYNTAX ERROR — refusing to apply. Nothing changed." >&2
  exit 1
fi
echo "    OK."

echo "[2/5] Snapshotting current live ruleset -> $SNAPSHOT"
nft list ruleset > "$SNAPSHOT"
echo "    Saved $(wc -l < "$SNAPSHOT") lines."

echo "[3/5] Arming auto-revert: old ruleset restores in ${TIMEOUT}s unless confirmed."
rm -f "$CONFIRM_FLAG"
# Background watchdog: wait TIMEOUT, then if no confirm flag, restore snapshot.
(
  sleep "$TIMEOUT"
  if [[ ! -f "$CONFIRM_FLAG" ]]; then
    nft flush ruleset
    nft -f "$SNAPSHOT"
    logger "safe_apply_nft: auto-reverted to snapshot (no confirmation received)"
  fi
) &
WATCHDOG_PID=$!

echo "[4/5] Applying new ruleset NOW..."
nft -f "$NEW_RULES"
echo "    Applied. Auto-revert in ${TIMEOUT}s unless you confirm."

echo "[5/5] CONFIRM you still have connectivity and want to KEEP these rules."
echo "    If your SSH still works, type 'yes' + Enter within ${TIMEOUT}s."
echo "    If anything broke, do NOTHING — it reverts automatically."
echo ""

# Read with a timeout. If the session is dead, this read never completes,
# the watchdog fires, and the old ruleset comes back.
if read -t "$TIMEOUT" -p "Keep these rules? (yes/no): " answer && [[ "$answer" == "yes" ]]; then
  touch "$CONFIRM_FLAG"
  # Cancel the watchdog cleanly.
  kill "$WATCHDOG_PID" 2>/dev/null || true
  echo ""
  echo "CONFIRMED — new ruleset kept. Snapshot left at $SNAPSHOT for manual rollback if needed."
else
  echo ""
  echo "Not confirmed — letting the watchdog restore the snapshot. Old rules coming back."
  # Don't kill the watchdog; let it do the revert.
fi
