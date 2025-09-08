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

view_file() {
    local log="$1" title="$2"
    if [ -f "$log" ]; then
        if [ "$USE_DIALOG" -eq 1 ]; then
            local tmp
            tmp=$(mktemp)
            tail -n 50 "$log" > "$tmp"
            dialog --backtitle "Kali IDS" --title "$title" --textbox "$tmp" 20 70
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

block_ip() {
    local ip="$1"
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "$ip already blocked"
        return
    fi
    iptables -A INPUT -s "$ip" -j DROP 2>/dev/null
    python3 - <<PY
import json, pathlib, time
ip="${ip}"
state=pathlib.Path("/var/lib/nn_ids/autoblock_state.json")
data={'counts':{},'blocked':{},'pos':0}
if state.exists():
    data=json.loads(state.read_text() or '{}')
data.setdefault('blocked',{})[ip]=time.time()
state.parent.mkdir(parents=True, exist_ok=True)
state.write_text(json.dumps(data))
PY
    echo "Blocked $ip"
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

manage_blocked() {
    while true; do
        if [ "$USE_DIALOG" -eq 1 ]; then
            local blocked opts choice ip
            blocked=$(list_blocked)
            choice=$(dialog --clear --backtitle "Kali IDS" --title "Blocked IPs" \
                --menu "Select action:" 20 70 5 \
                1 "List blocked IPs" \
                2 "Block an IP" \
                3 "Unblock an IP" \
                4 "Clear all" \
                5 "Return" 3>&1 1>&2 2>&3) || break
            case "$choice" in
                1)
                    dialog --backtitle "Kali IDS" --title "Blocked IPs" --msgbox "${blocked:-None}" 20 50;
                    ;;
                2)
                    ip=$(dialog --inputbox "Enter IP to block:" 8 40 "" 3>&1 1>&2 2>&3) || continue
                    [ -n "$ip" ] && block_ip "$ip"
                    ;;
                3)
                    ip=$(dialog --inputbox "Enter IP to unblock:" 8 40 "" 3>&1 1>&2 2>&3) || continue
                    [ -n "$ip" ] && unblock_ip "$ip"
                    ;;
                4)
                    clear_all_blocked ;;
                5)
                    break ;;
            esac
        else
            echo "Blocked IPs:"; list_blocked
            echo "1) Block an IP"
            echo "2) Unblock an IP"
            echo "3) Clear all"
            echo "4) Return"
            read -rp "Choose: " choice
            case "$choice" in
                1)
                    read -rp "IP to block: " ip
                    [ -n "$ip" ] && block_ip "$ip"
                    ;;
                2)
                    read -rp "IP to unblock: " ip
                    [ -n "$ip" ] && unblock_ip "$ip"
                    ;;
                3)
                    clear_all_blocked ;;
                4)
                    break ;;
                *) echo "Invalid" ;;
            esac
        fi
    done
}

view_logs() {
    view_file "/var/log/nn_ids_service.log" "Recent IDS Alerts"
}

view_training() {
    view_file "/var/log/nn_ids_train.log" "Training Metrics"
}

view_report() {
    view_file "/var/log/nn_ids_report.log" "Alert Report"
}

view_feed_log() {
    view_file "/var/log/threat_feed_blocklist.log" "Threat Feed Log"
}

view_autoblock_log() {
    view_file "/var/log/nn_ids_autoblock.log" "Autoblock Actions"
}

view_process_alerts() {
    view_file "/var/log/process_monitor_alerts.log" "Process Monitor Alerts"
}

view_anti_wipe_log() {
    view_file "/var/log/anti_wipe.log" "Anti-Wipe Monitor"
}

view_resource_log() {
    view_file "/var/log/nn_ids_resource.log" "IDS Resource Log"
}

view_port_alerts() {
    view_file "/var/log/port_monitor_alerts.log" "Port Monitor Alerts"
}

view_rkhunter_log() {
    view_file "/var/log/rkhunter.log" "rkhunter Scan Log"
}

view_lynis_log() {
    view_file "/var/log/lynis.log" "Lynis Scan Log"
}

view_clamav_log() {
    view_file "/var/log/clamav.log" "ClamAV Scan Log"
}

run_rkhunter_scan() {
    if command -v rkhunter >/dev/null 2>&1; then
        rkhunter --check --sk >/var/log/rkhunter.log 2>&1
        show_msg "rkhunter scan complete"
    else
        show_msg "rkhunter not installed"
    fi
}

run_lynis_scan() {
    if command -v lynis >/dev/null 2>&1; then
        lynis audit system >/var/log/lynis.log 2>&1
        show_msg "Lynis audit complete"
    else
        show_msg "Lynis not installed"
    fi
}

run_clamav_scan() {
    if command -v clamscan >/dev/null 2>&1; then
        clamscan -ri / >/var/log/clamav.log 2>&1
        show_msg "ClamAV scan complete"
    else
        show_msg "ClamAV not installed"
    fi
}

run_all_scans() {
    run_rkhunter_scan
    run_lynis_scan
    run_clamav_scan
    summarize_scan_logs
}

summarize_scan_logs() {
    local tmp
    tmp=$(mktemp)
    if python3 /usr/local/bin/scan_log_summary.py >"$tmp" 2>/dev/null; then
        view_file "$tmp" "Scan Summary"
    else
        show_msg "scan_log_summary.py not found"
    fi
    rm -f "$tmp"
}

view_network_io_logs() {
    if [ "$USE_DIALOG" -eq 1 ]; then
        local choice
        choice=$(dialog --backtitle "Kali IDS" --title "Network I/O Logs" --menu "Select log:" 20 70 4 \
            1 "Inbound IPv4" \
            2 "Outbound IPv4" \
            3 "Inbound IPv6" \
            4 "Outbound IPv6" 3>&1 1>&2 2>&3) || return
    else
        echo "1) Inbound IPv4"
        echo "2) Outbound IPv4"
        echo "3) Inbound IPv6"
        echo "4) Outbound IPv6"
        read -rp "Choose: " choice
    fi
    case "$choice" in
        1) view_file "/var/log/inbound.log" "Inbound IPv4" ;;
        2) view_file "/var/log/outbound.log" "Outbound IPv4" ;;
        3) view_file "/var/log/inbound6.log" "Inbound IPv6" ;;
        4) view_file "/var/log/outbound6.log" "Outbound IPv6" ;;
    esac
}

view_discovery_report() {
    local report="/home/kali/Desktop/initial network discovery/network_discovery_report.html"
    if [ -f "$report" ]; then
        if command -v xdg-open >/dev/null 2>&1; then
            xdg-open "$report" >/dev/null 2>&1 &
            show_msg "Opened network discovery report"
        elif command -v sensible-browser >/dev/null 2>&1; then
            sensible-browser "$report" >/dev/null 2>&1 &
            show_msg "Opened network discovery report"
        else
            view_file "$report" "Network Discovery Report"
        fi
    else
        show_msg "No network discovery report found"
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

generate_adversarial() {
    trigger_or_run nn_ids_adversarial.service nn_ids_adversarial.py
    show_msg "Adversarial samples generated"
}

snapshot_now() {
    trigger_or_run nn_ids_snapshot.service nn_ids_snapshot.py
    show_msg "Snapshot created"
}

restore_now() {
    trigger_or_run nn_ids_restore.service nn_ids_restore.py
    show_msg "Restore started"
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
        choice=$(dialog --clear --colors --backtitle "Kali IDS" --title "IDS Dashboard" --menu "Select an option:" 20 75 26 \
            1 "Toggle notifications [$(status_dialog "$notify")]" \
            2 "Set discovery response [\Z6$discovery\Zn]" \
            3 "Toggle packet sanitization [$(status_dialog "$sanitize")]" \
            4 "Toggle automatic IP blocking [$(status_dialog "$autoblock")]" \
            5 "Toggle threat feed blocking [$(status_dialog "$feed")]" \
            6 "Manage blocked IPs" \
            7 "View recent IDS alerts" \
            8 "View training metrics" \
            9 "View alert report" \
            10 "View threat feed log" \
            11 "Run network discovery" \
            12 "View network discovery report" \
            13 "Sanitize datasets now" \
            14 "Retrain IDS model" \
            15 "Update threat feed" \
            16 "Snapshot IDS state" \
            17 "Restore IDS state" \
            18 "Generate adversarial samples" \
            19 "Restart IDS service" \
            20 "View network I/O logs" \
            21 "View port monitor alerts" \
            22 "View autoblock log" \
            23 "View process monitor alerts" \
            24 "View anti-wipe log" \
            25 "View IDS resource log" \
            26 "View rkhunter log" \
            27 "View Lynis log" \
            28 "View ClamAV log" \
            29 "Run rkhunter scan" \
            30 "Run Lynis audit" \
            31 "Run ClamAV scan" \
            32 "Run all scans" \
            33 "Summarize scan logs" \
            34 "Exit" 3>&1 1>&2 2>&3) || break
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
        echo -e "${GREEN}8)${RESET} View training metrics"
        echo -e "${GREEN}9)${RESET} View alert report"
        echo -e "${GREEN}10)${RESET} View threat feed log"
        echo -e "${GREEN}11)${RESET} Run network discovery"
        echo -e "${GREEN}12)${RESET} View network discovery report"
        echo -e "${GREEN}13)${RESET} Sanitize datasets now"
        echo -e "${GREEN}14)${RESET} Retrain IDS model"
        echo -e "${GREEN}15)${RESET} Update threat feed"
        echo -e "${GREEN}16)${RESET} Snapshot IDS state"
        echo -e "${GREEN}17)${RESET} Restore IDS state"
        echo -e "${GREEN}18)${RESET} Generate adversarial samples"
        echo -e "${GREEN}19)${RESET} Restart IDS service"
        echo -e "${GREEN}20)${RESET} View network I/O logs"
        echo -e "${GREEN}21)${RESET} View port monitor alerts"
        echo -e "${GREEN}22)${RESET} View autoblock log"
        echo -e "${GREEN}23)${RESET} View process monitor alerts"
        echo -e "${GREEN}24)${RESET} View anti-wipe log"
        echo -e "${GREEN}25)${RESET} View IDS resource log"
        echo -e "${GREEN}26)${RESET} View rkhunter log"
        echo -e "${GREEN}27)${RESET} View Lynis log"
        echo -e "${GREEN}28)${RESET} View ClamAV log"
        echo -e "${GREEN}29)${RESET} Run rkhunter scan"
        echo -e "${GREEN}30)${RESET} Run Lynis audit"
        echo -e "${GREEN}31)${RESET} Run ClamAV scan"
        echo -e "${GREEN}32)${RESET} Run all scans"
        echo -e "${GREEN}33)${RESET} Summarize scan logs"
        echo -e "${GREEN}34)${RESET} Exit"
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
            manage_blocked
            ;;
        7)
            view_logs
            ;;
        8)
            view_training
            ;;
        9)
            view_report
            ;;
        10)
            view_feed_log
            ;;
        11)
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
        12)
            view_discovery_report
            ;;
        13)
            sanitize_now
            ;;
        14)
            retrain_now
            ;;
        15)
            update_threat_feed
            ;;
        16)
            snapshot_now
            ;;
        17)
            restore_now
            ;;
        18)
            generate_adversarial
            ;;
        19)
            if systemctl restart nn_ids.service; then
                show_msg "IDS service restarted"
            else
                show_msg "Failed to restart IDS service"
            fi
            ;;
        20)
            view_network_io_logs
            ;;
        21)
            view_port_alerts
            ;;
        22)
            view_autoblock_log
            ;;
        23)
            view_process_alerts
            ;;
        24)
            view_anti_wipe_log
            ;;
        25)
            view_resource_log
            ;;
        26)
            view_rkhunter_log
            ;;
        27)
            view_lynis_log
            ;;
        28)
            view_clamav_log
            ;;
        29)
            run_rkhunter_scan
            ;;
        30)
            run_lynis_scan
            ;;
        31)
            run_clamav_scan
            ;;
        32)
            run_all_scans
            ;;
        33)
            summarize_scan_logs
            ;;
        34)
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
