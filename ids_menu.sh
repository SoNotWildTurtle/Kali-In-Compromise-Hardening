#!/bin/bash
# ids_menu.sh - Configure IDS options and manage blocked IPs

if command -v tput >/dev/null 2>&1; then
    BLUE=$(tput setaf 4)
    GREEN=$(tput setaf 2)
    RED=$(tput setaf 1)
    RESET=$(tput sgr0)
else
    BLUE=""
    GREEN=""
    RED=""
    RESET=""
fi

# Use dialog for a friendlier dashboard when available
if command -v dialog >/dev/null 2>&1; then
    USE_DIALOG=1
else
    USE_DIALOG=0
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

trigger_or_run() {
    local svc="$1"
    local script="$2"
    if systemctl list-unit-files | grep -q "$svc"; then
        systemctl start "$svc" >/dev/null 2>&1
    else
        python3 "/usr/local/bin/$script" >/dev/null 2>&1
    fi
}

show_msg() {
    local msg="$1"
    if [ "$USE_DIALOG" -eq 1 ]; then
        dialog --msgbox "$msg" 6 50
    else
        echo "$msg"
    fi
}

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
        if [ "$USE_DIALOG" -eq 1 ]; then
            local tmp
            tmp=$(mktemp)
            tail -n 50 "$log" > "$tmp"
            dialog --backtitle "Kali IDS" --title "Recent IDS Alerts" --textbox "$tmp" 20 70
            rm -f "$tmp"
        else
            tail -n 50 "$log" | ${PAGER:-less}
        fi
    else
        if [ "$USE_DIALOG" -eq 1 ]; then
            dialog --msgbox "No log file at $log" 6 40
        else
            echo "No log file at $log"
            read -rp "Press Enter to return" _
        fi
    fi
}

sanitize_now() {
    trigger_or_run nn_ids_sanitize.service nn_ids_sanitize.py
    show_msg "Dataset sanitization triggered"
}

retrain_now() {
    trigger_or_run nn_ids_retrain.service nn_ids_retrain.py
    show_msg "Model retraining started"
}

update_threat_feed() {
    trigger_or_run threat_feed_blocklist.service threat_feed_blocklist.py
    show_msg "Threat feed update triggered"
}

status_word() {
    [ "$1" = "1" ] && echo "ON" || echo "OFF"
}

status_dialog() {
    if [ "$1" = "1" ]; then
        echo "\Z2ON\Zn"
    else
        echo "\Z1OFF\Zn"
    fi
}

while true; do
    notify=$(get_value NN_IDS_NOTIFY)
    discovery=$(get_value NN_IDS_DISCOVERY_MODE)
    sanitize=$(get_value NN_IDS_SANITIZE)
    autoblock=$(get_value NN_IDS_AUTOBLOCK)
    feed=$(get_value NN_IDS_THREAT_FEED)
    if [ "$USE_DIALOG" -eq 1 ]; then
        choice=$(dialog --clear --colors --backtitle "Kali IDS" --title "IDS Dashboard" --menu "Select an option:" 20 75 13 \
            1 "Toggle notifications [$(status_dialog "$notify")]" \
            2 "Set discovery response [\Z6$discovery\Zn]" \
            3 "Toggle packet sanitization [$(status_dialog "$sanitize")]" \
            4 "Toggle automatic IP blocking [$(status_dialog "$autoblock")]" \
            5 "Toggle threat feed blocking [$(status_dialog "$feed")]" \
            6 "Manage blocked IPs" \
            7 "View recent IDS alerts" \
            8 "Run network discovery" \
            9 "Sanitize datasets now" \
            10 "Retrain IDS model" \
            11 "Update threat feed" \
            12 "Exit" 3>&1 1>&2 2>&3) || break
    else
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
        echo -e "${GREEN}9)${RESET} Sanitize datasets now"
        echo -e "${GREEN}10)${RESET} Retrain IDS model"
        echo -e "${GREEN}11)${RESET} Update threat feed"
        echo -e "${GREEN}12)${RESET} Exit"
        read -rp "Choose an option: " choice
    fi
    case "$choice" in
        1)
            if [ "$notify" = "1" ]; then
                notify=0
            else
                notify=1
            fi
            set_value NN_IDS_NOTIFY "$notify"
            if [ "$USE_DIALOG" -eq 1 ]; then
                dialog --msgbox "Notifications $(status_word "$notify")" 6 40
            else
                echo "Notification setting updated to $notify"
            fi
            ;;
        2)
            if [ "$USE_DIALOG" -eq 1 ]; then
                resp=$(dialog --clear --title "Discovery Mode" --menu "Select response mode:" 15 60 4 \
                    auto "Run automatically" \
                    manual "Prompt before running" \
                    notify "Only notify" \
                    none "No response" 3>&1 1>&2 2>&3) || continue
                discovery="$resp"
            else
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
            fi
            set_value NN_IDS_DISCOVERY_MODE "$discovery"
            if [ "$USE_DIALOG" -eq 1 ]; then
                dialog --msgbox "Discovery mode set to $discovery" 6 50
            else
                echo "Discovery mode set to $discovery"
            fi
            ;;
        3)
            if [ "$sanitize" = "1" ]; then
                sanitize=0
            else
                sanitize=1
            fi
            set_value NN_IDS_SANITIZE "$sanitize"
            if [ "$USE_DIALOG" -eq 1 ]; then
                dialog --msgbox "Packet sanitization $(status_word "$sanitize")" 6 50
            else
                echo "Packet sanitization set to $sanitize"
            fi
            ;;
        4)
            if [ "$autoblock" = "1" ]; then
                autoblock=0
            else
                autoblock=1
            fi
            set_value NN_IDS_AUTOBLOCK "$autoblock"
            if [ "$USE_DIALOG" -eq 1 ]; then
                dialog --msgbox "Automatic IP blocking $(status_word "$autoblock")" 6 60
            else
                echo "Automatic IP blocking set to $autoblock"
            fi
            ;;
        5)
            if [ "$feed" = "1" ]; then
                feed=0
            else
                feed=1
            fi
            set_value NN_IDS_THREAT_FEED "$feed"
            if [ "$USE_DIALOG" -eq 1 ]; then
                dialog --msgbox "Threat feed blocking $(status_word "$feed")" 6 60
            else
                echo "Threat feed blocking set to $feed"
            fi
            ;;
        6)
            if [ "$USE_DIALOG" -eq 1 ]; then
                blocked=$(list_blocked)
                dialog --backtitle "Kali IDS" --title "Blocked IPs" --msgbox "${blocked:-None}" 20 50
                ip=$(dialog --inputbox "Enter IP to unblock or 'all' to clear:" 8 50 "" 3>&1 1>&2 2>&3) || continue
            else
                list_blocked
                read -rp "Enter IP to unblock, 'all' to clear, or press Enter to return: " ip
            fi
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
                if [ "$USE_DIALOG" -eq 1 ]; then
                    dialog --msgbox "Network discovery complete" 6 40
                fi
            else
                if [ "$USE_DIALOG" -eq 1 ]; then
                    dialog --msgbox "network_discovery.sh not found" 6 40
                else
                    echo "network_discovery.sh not found"
                fi
            fi
            ;;
        9)
            sanitize_now
            ;;
        10)
            retrain_now
            ;;
        11)
            update_threat_feed
            ;;
        12)
            if [ "$USE_DIALOG" -eq 1 ]; then
                dialog --msgbox "Exiting" 5 20
            else
                echo "Exiting."
            fi
            break
            ;;
        *)
            if [ "$USE_DIALOG" -eq 1 ]; then
                dialog --msgbox "Invalid option" 5 20
            else
                echo "Invalid option"
            fi
            ;;
    esac
done
