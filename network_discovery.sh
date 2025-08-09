#!/bin/bash
# network_discovery.sh - perform comprehensive local network discovery and diagnostics

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
OUTPUT_DIR="/home/kali/Desktop/initial network discovery"
mkdir -p "$OUTPUT_DIR"

INBOUND_PORT=${INBOUND_PORT:-5775}
OUTBOUND_PORT=${OUTBOUND_PORT:-7557}

# Determine local network range
NET_RANGE=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -n1)

if [ -n "$NET_RANGE" ]; then
    nmap -sn "$NET_RANGE" -oN "$OUTPUT_DIR/network_hosts.txt"
    nmap -sV -O "$NET_RANGE" -oN "$OUTPUT_DIR/network_services.txt" -oX "$OUTPUT_DIR/network_services.xml"

    command -v netdiscover >/dev/null 2>&1 && netdiscover -PN -r "$NET_RANGE" > "$OUTPUT_DIR/netdiscover.txt"
    command -v arp-scan >/dev/null 2>&1 && arp-scan --localnet > "$OUTPUT_DIR/arp_scan.txt"
    command -v nbtscan >/dev/null 2>&1 && nbtscan -r "$NET_RANGE" > "$OUTPUT_DIR/nbtscan.txt"

    DNS_SERVER=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)
    if command -v dnsrecon >/dev/null 2>&1 && [ -n "$DNS_SERVER" ]; then
        dnsrecon -r "$NET_RANGE" -n "$DNS_SERVER" > "$OUTPUT_DIR/dnsrecon.txt"
    fi

    HOSTS=$(awk '/Nmap scan report for/ {print $NF}' "$OUTPUT_DIR/network_hosts.txt" | tr -d '()')
    for ip in $HOSTS; do
        command -v whatweb >/dev/null 2>&1 && whatweb -q "$ip" >> "$OUTPUT_DIR/whatweb.txt"
        command -v enum4linux >/dev/null 2>&1 && enum4linux -a "$ip" > "$OUTPUT_DIR/enum4linux_${ip}.txt"
    done
fi

# Current network connections and sockets
ss -tulpen > "$OUTPUT_DIR/current_connections.txt"
lsof -i -P -n > "$OUTPUT_DIR/lsof_connections.txt"
arp -a > "$OUTPUT_DIR/arp_table.txt" || true
ip route > "$OUTPUT_DIR/ip_route.txt"
ip addr > "$OUTPUT_DIR/ip_addr.txt"
command -v traceroute >/dev/null 2>&1 && traceroute -n 8.8.8.8 > "$OUTPUT_DIR/traceroute.txt" || true

# System diagnostics
uname -a > "$OUTPUT_DIR/system_info.txt"
command -v lshw >/dev/null 2>&1 && lshw -short > "$OUTPUT_DIR/hardware_summary.txt"
df -h > "$OUTPUT_DIR/disk_usage.txt"
free -h > "$OUTPUT_DIR/memory_usage.txt"
ps aux > "$OUTPUT_DIR/running_processes.txt"
command -v hostnamectl >/dev/null 2>&1 && hostnamectl > "$OUTPUT_DIR/hostnamectl.txt"

# Verify enforced port separation on localhost
nmap -Pn -p "$INBOUND_PORT","$OUTBOUND_PORT" localhost \
    -oN "$OUTPUT_DIR/port_separation.txt"

# Generate visualization report
if command -v python3 >/dev/null 2>&1; then
    python3 "$SCRIPT_DIR/network_discovery_visualize.py" "$OUTPUT_DIR" || true
fi

echo "Initial network discovery complete. Logs saved to $OUTPUT_DIR"
