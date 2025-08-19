#!/bin/bash
# ids_menu.sh - Configure IDS options and manage blocked IPs

if command -v tput >/dev/null 2>&1; then
    BLUE=$(tput setaf 4)
    GREEN=$(tput setaf 2)
    RESET=$(tput sgr0)
else
    BLUE=""
    GREEN=""
    RESET=""
fi

CONF_FILE="/etc/nn_ids.conf"
[ -w "$CONF_FILE" ] || CONF_FILE="$(dirname "$0")/nn_ids.conf"

get_value() {
    grep -E "^$1=" "$CONF_FILE" | cut -d'=' -f2
}

set_value() {
    if grep -qE "^$1=" "$CONF_FILE"; then
        sed -i "s/^$1=.*/$1=$2/" "$CONF_FILE"
    else
        echo "$1=$2" >> "$CONF_FILE"
    fi
}

STATE_AUTO="/var/lib/nn_ids/autoblock_state.json"
STATE_FEED="/var/lib/nn_ids/threat_feed_state.json"

list_blocked() {
    python3 - <<'PY'
import json, pathlib
paths=[
    (pathlib.Path("/var/lib/nn_ids/autoblock_state.json"), "Autoblock"),
    (pathlib.Path("/var/lib/nn_ids/threat_feed_state.json"), "Threat Feed"),
]
for p,label in paths:
    if p.exists():
        data=json.loads(p.read_text() or '{}')
        if label=="Autoblock":
            ips=list(data.get("blocked", {}).keys())
        else:
            ips=data.get("blocked", [])
        if ips:
            print(f"{label}:")
            for ip in ips:
                print(f"  {ip}")
PY
}

unblock_ip() {
    local ip="$1"
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
    python3 - <<PY
import json, pathlib
ip="${ip}"
auto=pathlib.Path("/var/lib/nn_ids/autoblock_state.json")
if auto.exists():
    data=json.loads(auto.read_text() or '{}')
    data.get('blocked', {}).pop(ip, None)
    data.get('counts', {}).pop(ip, None)
    auto.write_text(json.dumps(data))
feed=pathlib.Path("/var/lib/nn_ids/threat_feed_state.json")
if feed.exists():
    data=json.loads(feed.read_text() or '{}')
    if ip in data.get('blocked', []):
        data['blocked'].remove(ip)
        feed.write_text(json.dumps(data))
PY
    echo "Unblocked $ip"
}

clear_all_blocked() {
    python3 - <<'PY'
import json, pathlib, subprocess
auto=pathlib.Path("/var/lib/nn_ids/autoblock_state.json")
if auto.exists():
    data=json.loads(auto.read_text() or '{}')
    for ip in list(data.get('blocked', {}).keys()):
        subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    auto.write_text(json.dumps({'counts':{}, 'blocked':{}, 'pos': data.get('pos',0)}))
feed=pathlib.Path("/var/lib/nn_ids/threat_feed_state.json")
if feed.exists():
    data=json.loads(feed.read_text() or '{}')
    for ip in data.get('blocked', []):
        subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    feed.write_text(json.dumps({'blocked': []}))
PY
    echo "Cleared all blocked IPs"
}

view_logs() {
    local log="/var/log/nn_ids_service.log"
    if [ -f "$log" ]; then
        tail -n 50 "$log" | ${PAGER:-less}
    else
        echo "No log file at $log"
        read -rp "Press Enter to return" _
    fi
}

while true; do
    notify=$(get_value NN_IDS_NOTIFY)
    discovery=$(get_value NN_IDS_DISCOVERY_MODE)
    sanitize=$(get_value NN_IDS_SANITIZE)
    autoblock=$(get_value NN_IDS_AUTOBLOCK)
    feed=$(get_value NN_IDS_THREAT_FEED)
    clear
    echo -e "${BLUE}IDS Control Menu${RESET}"
    echo -e "${GREEN}1)${RESET} Toggle malicious packet notifications (currently: $notify)"
    echo -e "${GREEN}2)${RESET} Set network discovery response (currently: $discovery)"
    echo -e "${GREEN}3)${RESET} Toggle packet sanitization (currently: $sanitize)"
    echo -e "${GREEN}4)${RESET} Toggle automatic IP blocking (currently: $autoblock)"
    echo -e "${GREEN}5)${RESET} Toggle threat feed blocking (currently: $feed)"
    echo -e "${GREEN}6)${RESET} Manage blocked IP addresses"
    echo -e "${GREEN}7)${RESET} View recent IDS alerts"
    echo -e "${GREEN}8)${RESET} Run network discovery"
    echo -e "${GREEN}9)${RESET} Exit"
    read -rp "Choose an option: " choice
    case "$choice" in
        1)
            if [ "$notify" = "1" ]; then
                notify=0
            else
                notify=1
            fi
            set_value NN_IDS_NOTIFY "$notify"
            echo "Notification setting updated to $notify"
            ;;
        2)
            echo "Select response mode:"
            echo "a) auto"
            echo "b) manual"
            echo "c) notify"
            echo "d) none"
            read -rp "Response choice: " resp
            case "$resp" in
                a|A) discovery="auto" ;;
                b|B) discovery="manual" ;;
                c|C) discovery="notify" ;;
                d|D) discovery="none" ;;
                *) echo "Invalid"; continue ;;
            esac
            set_value NN_IDS_DISCOVERY_MODE "$discovery"
            echo "Discovery mode set to $discovery"
            ;;
        3)
            if [ "$sanitize" = "1" ]; then
                sanitize=0
            else
                sanitize=1
            fi
            set_value NN_IDS_SANITIZE "$sanitize"
            echo "Packet sanitization set to $sanitize"
            ;;
        4)
            if [ "$autoblock" = "1" ]; then
                autoblock=0
            else
                autoblock=1
            fi
            set_value NN_IDS_AUTOBLOCK "$autoblock"
            echo "Automatic IP blocking set to $autoblock"
            ;;
        5)
            if [ "$feed" = "1" ]; then
                feed=0
            else
                feed=1
            fi
            set_value NN_IDS_THREAT_FEED "$feed"
            echo "Threat feed blocking set to $feed"
            ;;
        6)
            list_blocked
            read -rp "Enter IP to unblock, 'all' to clear, or press Enter to return: " ip
            if [ "$ip" = "all" ]; then
                clear_all_blocked
            elif [ -n "$ip" ]; then
                unblock_ip "$ip"
            fi
            ;;
        7)
            view_logs
            ;;
        8)
            if [ -x /usr/local/bin/network_discovery.sh ]; then
                /usr/local/bin/network_discovery.sh
            else
                echo "network_discovery.sh not found"
            fi
            ;;
        9)
            echo "Exiting."; break ;;
        *)
            echo "Invalid option" ;;
    esac
done
