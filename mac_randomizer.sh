#!/bin/bash
# mac_randomizer.sh - randomize MAC address on boot
set -euo pipefail

IFACE="${1:-$(ip route | awk '/default/ {print $5; exit}') }"

if [ -n "$IFACE" ] && command -v macchanger >/dev/null 2>&1; then
    ip link set "$IFACE" down
    macchanger -r "$IFACE"
    ip link set "$IFACE" up
fi
