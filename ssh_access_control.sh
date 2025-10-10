#!/bin/bash
# ssh_access_control.sh - Apply SSH whitelist and blacklist rules

WHITELIST_CONF="/etc/ssh_whitelist.conf"
BLACKLIST_CONF="/etc/ssh_blacklist.conf"

# Fallback to script directory if configs not in /etc
[ -f "$WHITELIST_CONF" ] || WHITELIST_CONF="$(dirname "$0")/ssh_whitelist.conf"
[ -f "$BLACKLIST_CONF" ] || BLACKLIST_CONF="$(dirname "$0")/ssh_blacklist.conf"

CHAIN="SSH_ACCESS"

# Create or flush custom chain
iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -C INPUT -p tcp --dport 22 -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 22 -j "$CHAIN"

# Apply blacklist rules
if [ -f "$BLACKLIST_CONF" ]; then
    grep -Eo '^[0-9./]+' "$BLACKLIST_CONF" | while read -r ip; do
        [ -n "$ip" ] && iptables -A "$CHAIN" -s "$ip" -j DROP
    done
fi

# Apply whitelist rules
if [ -f "$WHITELIST_CONF" ]; then
    WL_IPS=$(grep -Eo '^[0-9./]+' "$WHITELIST_CONF")
    if [ -n "$WL_IPS" ]; then
        while read -r ip; do
            [ -n "$ip" ] && iptables -A "$CHAIN" -s "$ip" -j ACCEPT
        done <<< "$WL_IPS"
        iptables -A "$CHAIN" -j DROP
    else
        iptables -A "$CHAIN" -j ACCEPT
    fi
else
    iptables -A "$CHAIN" -j ACCEPT
fi
