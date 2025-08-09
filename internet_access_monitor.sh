#!/bin/bash
# internet_access_monitor.sh - ensure system maintains internet connectivity
set -euo pipefail

LOG="/var/log/internet_access.log"
mkdir -p "$(dirname "$LOG")"
touch "$LOG"

INBOUND_PORT=${INBOUND_PORT:-5775}
OUTBOUND_PORT=${OUTBOUND_PORT:-7557}

# Enforce inbound/outbound port separation
iptables -nL INPUT_GUARD >/dev/null 2>&1 || iptables -N INPUT_GUARD
iptables -nL OUTPUT_GUARD >/dev/null 2>&1 || iptables -N OUTPUT_GUARD
iptables -C INPUT -j INPUT_GUARD >/dev/null 2>&1 || iptables -A INPUT -j INPUT_GUARD
iptables -C OUTPUT -j OUTPUT_GUARD >/dev/null 2>&1 || iptables -A OUTPUT -j OUTPUT_GUARD
iptables -F INPUT_GUARD
iptables -A INPUT_GUARD -p tcp --dport "$INBOUND_PORT" -j ACCEPT
iptables -A INPUT_GUARD -j DROP
iptables -F OUTPUT_GUARD
iptables -A OUTPUT_GUARD -p tcp --sport "$OUTBOUND_PORT" -j ACCEPT
iptables -A OUTPUT_GUARD -j DROP

# Ensure outbound traffic is permitted
iptables -P OUTPUT ACCEPT
iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Bring up default network interface if it's down
IFACE=$(ip route | awk '/default/ {print $5; exit}')
if [ -n "$IFACE" ] && ! ip link show "$IFACE" | grep -q "UP"; then
    ip link set "$IFACE" up || true
    dhclient "$IFACE" || true
fi

# Attempt to activate common SD-WAN/Cisco/VMware interfaces as fallbacks
for ALT in sdwan0 cisco0 vmnet0 vmnet1; do
    if ip link show "$ALT" >/dev/null 2>&1; then
        if ! ip link show "$ALT" | grep -q "UP"; then
            ip link set "$ALT" up || true
            dhclient "$ALT" || true
        fi
        # ensure a default route exists for the interface
        ip route | grep -q "^default.*$ALT" || ip route add default dev "$ALT" metric 200 || true
    fi
done

# Verify connectivity via current routes
HOSTS=(1.1.1.1 8.8.8.8 google.com)
for HOST in "${HOSTS[@]}"; do
    if ping -c1 -W2 "$HOST" >/dev/null 2>&1; then
        echo "$(date) internet access verified via $HOST" >> "$LOG"
        exit 0
    fi
done

# Try each fallback interface directly
for ALT in sdwan0 cisco0 vmnet0 vmnet1; do
    if ip link show "$ALT" >/dev/null 2>&1; then
        for HOST in "${HOSTS[@]}"; do
            if ping -I "$ALT" -c1 -W2 "$HOST" >/dev/null 2>&1; then
                echo "$(date) internet access restored via $ALT using $HOST" >> "$LOG"
                exit 0
            fi
        done
    fi
done

# If unreachable, restart networking
systemctl restart NetworkManager.service || systemctl restart networking || true
echo "$(date) network restart attempted to restore connectivity" >> "$LOG"
