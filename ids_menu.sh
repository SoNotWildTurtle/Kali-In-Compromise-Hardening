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

prompt_float_value() {
    local key="$1" prompt="$2" min="$3" max="$4" current value
    current=$(get_value "$key")
    while true; do
        if [ "$USE_DIALOG" -eq 1 ]; then
            value=$(dialog --inputbox "$prompt\nRange: $min - $max" 9 60 "$current" 3>&1 1>&2 2>&3) || return 1
        else
            read -rp "$prompt [$current]: " value
            value=${value:-$current}
        fi
        value="${value//[[:space:]]/}"
        if [ -z "$value" ]; then
            show_msg "Value cannot be empty"
            continue
        fi
        if python3 - "$value" "$min" "$max" <<'PY' >/dev/null 2>&1
import sys
val = float(sys.argv[1])
lo = float(sys.argv[2])
hi = float(sys.argv[3])
if not lo <= val <= hi:
    raise SystemExit(1)
PY
        then
            set_value "$key" "$value"
            show_msg "$key set to $value"
            return 0
        else
            show_msg "Enter a numeric value between $min and $max"
        fi
    done
}

prompt_int_value() {
    local key="$1" prompt="$2" min="$3" max="$4" current value
    current=$(get_value "$key")
    while true; do
        if [ "$USE_DIALOG" -eq 1 ]; then
            value=$(dialog --inputbox "$prompt\nRange: $min - $max" 9 60 "$current" 3>&1 1>&2 2>&3) || return 1
        else
            read -rp "$prompt [$current]: " value
            value=${value:-$current}
        fi
        value="${value//[[:space:]]/}"
        if [ -z "$value" ]; then
            show_msg "Value cannot be empty"
            continue
        fi
        if python3 - "$value" "$min" "$max" <<'PY' >/dev/null 2>&1
import sys
try:
    val = int(sys.argv[1])
except ValueError:
    raise SystemExit(1)
lo = int(float(sys.argv[2]))
hi = int(float(sys.argv[3]))
if not lo <= val <= hi:
    raise SystemExit(1)
PY
        then
            set_value "$key" "$value"
            show_msg "$key set to $value"
            return 0
        else
            show_msg "Enter an integer between $min and $max"
        fi
    done
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
    view_file "/var/log/nn_ids_alerts.log" "Recent IDS Alerts"
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

run_ga_process_scan() {
    local proc_thresh proc_risk
    proc_thresh=$(get_value GA_PROC_THRESHOLD)
    proc_risk=$(get_value GA_PROC_MIN_RISK)
    GA_PROC_THRESHOLD=${proc_thresh:-0.5} GA_PROC_MIN_RISK=${proc_risk:-0.6} \
        python3 /usr/local/bin/nn_process_gt.py --scan >/dev/null 2>&1
    view_file "/var/log/ga_tech_proc_alerts.log" "GA Tech Process Alerts"
}

retrain_ga_process_model() {
    local proc_thresh proc_risk
    proc_thresh=$(get_value GA_PROC_THRESHOLD)
    proc_risk=$(get_value GA_PROC_MIN_RISK)
    GA_PROC_THRESHOLD=${proc_thresh:-0.5} GA_PROC_MIN_RISK=${proc_risk:-0.6} \
        python3 /usr/local/bin/nn_process_gt.py --train >/dev/null 2>&1
}

view_ga_train_log() {
    view_file "/var/log/ga_tech_proc_train.log" "GA Tech Training Metrics"
}

monitor_ga_processes() {
    local tmp
    tmp=$(mktemp)
    local proc_thresh proc_risk
    proc_thresh=$(get_value GA_PROC_THRESHOLD)
    proc_risk=$(get_value GA_PROC_MIN_RISK)
    GA_PROC_THRESHOLD=${proc_thresh:-0.5} GA_PROC_MIN_RISK=${proc_risk:-0.6} \
        python3 /usr/local/bin/nn_process_gt.py --monitor --duration 180 --interval 30 --verbose >"$tmp" 2>&1
    if [ "$USE_DIALOG" -eq 1 ]; then
        if [ -s "$tmp" ]; then
            dialog --textbox "$tmp" 20 90
        else
            dialog --msgbox "No GA Tech process alerts were generated during the monitor window." 7 60
        fi
    else
        if [ -s "$tmp" ]; then
            cat "$tmp"
        else
            echo "No GA Tech process alerts were generated during the monitor window."
        fi
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
    view_file "/var/log/ga_tech_proc_alerts.log" "GA Tech Process Alerts"
}

summarize_ga_process_history() {
    local tmp
    tmp=$(mktemp)
    local proc_thresh proc_risk
    proc_thresh=$(get_value GA_PROC_THRESHOLD)
    proc_risk=$(get_value GA_PROC_MIN_RISK)
    GA_PROC_THRESHOLD=${proc_thresh:-0.5} GA_PROC_MIN_RISK=${proc_risk:-0.6} \
        python3 /usr/local/bin/nn_process_gt.py --summarize >"$tmp" 2>&1
    if [ "$USE_DIALOG" -eq 1 ]; then
        if [ -s "$tmp" ]; then
            dialog --textbox "$tmp" 20 90
        else
            dialog --msgbox "No GA Tech detections have been recorded yet." 7 70
        fi
    else
        if [ -s "$tmp" ]; then
            cat "$tmp"
        else
            echo "No GA Tech detections have been recorded yet."
        fi
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
}

refresh_ga_process_baseline() {
    local tmp
    tmp=$(mktemp)
    local proc_thresh proc_risk
    proc_thresh=$(get_value GA_PROC_THRESHOLD)
    proc_risk=$(get_value GA_PROC_MIN_RISK)
    GA_PROC_THRESHOLD=${proc_thresh:-0.5} GA_PROC_MIN_RISK=${proc_risk:-0.6} \
        python3 /usr/local/bin/nn_process_gt.py --refresh-baseline --verbose >"$tmp" 2>&1
    if [ "$USE_DIALOG" -eq 1 ]; then
        dialog --textbox "$tmp" 15 90
    else
        cat "$tmp"
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
}

view_ga_sys_alerts() {
    view_file "/var/log/ga_tech_sys_alerts.log" "GA Tech System Call Alerts"
}

view_ga_sys_train_log() {
    view_file "/var/log/ga_tech_sys_train.log" "GA Tech System Call Training"
}

monitor_ga_syscalls() {
    local tmp
    tmp=$(mktemp)
    local sys_thresh sys_window
    sys_thresh=$(get_value NN_SYS_THRESHOLD)
    sys_window=$(get_value NN_SYS_WINDOW)
    NN_SYS_THRESHOLD=${sys_thresh:-0.6} GA_SYS_THRESHOLD=${sys_thresh:-0.6} NN_SYS_WINDOW=${sys_window:-25} \
        python3 /usr/local/bin/nn_syscall_gt.py --scan --duration 180 --interval 0.5 --window "${sys_window:-25}" >"$tmp" 2>&1
    if [ "$USE_DIALOG" -eq 1 ]; then
        if [ -s "$tmp" ]; then
            dialog --textbox "$tmp" 20 90
        else
            dialog --msgbox "No GA Tech system call alerts were generated during the monitor window." 7 75
        fi
    else
        if [ -s "$tmp" ]; then
            cat "$tmp"
        else
            echo "No GA Tech system call alerts were generated during the monitor window."
        fi
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
    view_file "/var/log/ga_tech_sys_alerts.log" "GA Tech System Call Alerts"
}

retrain_ga_sys_model() {
    local sys_thresh sys_window
    sys_thresh=$(get_value NN_SYS_THRESHOLD)
    sys_window=$(get_value NN_SYS_WINDOW)
    NN_SYS_THRESHOLD=${sys_thresh:-0.6} GA_SYS_THRESHOLD=${sys_thresh:-0.6} NN_SYS_WINDOW=${sys_window:-25} \
        python3 /usr/local/bin/nn_syscall_gt.py --train >/dev/null 2>&1
}

summarize_ga_sys_detections() {
    local tmp
    tmp=$(mktemp)
    local sys_thresh sys_window
    sys_thresh=$(get_value NN_SYS_THRESHOLD)
    sys_window=$(get_value NN_SYS_WINDOW)
    NN_SYS_THRESHOLD=${sys_thresh:-0.6} GA_SYS_THRESHOLD=${sys_thresh:-0.6} NN_SYS_WINDOW=${sys_window:-25} \
        python3 /usr/local/bin/nn_syscall_gt.py --summarize >"$tmp" 2>&1
    if [ "$USE_DIALOG" -eq 1 ]; then
        if [ -s "$tmp" ]; then
            dialog --textbox "$tmp" 20 90
        else
            dialog --msgbox "No GA Tech system call detections have been recorded yet." 7 80
        fi
    else
        if [ -s "$tmp" ]; then
            cat "$tmp"
        else
            echo "No GA Tech system call detections have been recorded yet."
        fi
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
}

show_alert_stats() {
    local tmp
    tmp=$(mktemp)
    python3 - <<'PY' >"$tmp" 2>/dev/null
import json
import pathlib

path = pathlib.Path('/var/lib/nn_ids/alert_stats.json')
if not path.exists():
    print('No alerts have been recorded yet.')
else:
    try:
        data = json.loads(path.read_text() or '{}')
    except json.JSONDecodeError:
        print('Alert statistics are unavailable (corrupted data).')
    else:
        total = int(data.get('total_alerts', 0))
        high = int(data.get('high_confidence', 0))
        low = int(data.get('low_confidence', 0))
        last = data.get('last_alert', 'unknown')
        reason = data.get('last_reason', 'n/a')
        summary = data.get('last_summary', 'n/a')
        try:
            last_prob = float(data.get('last_probability', 0.0))
        except (TypeError, ValueError):
            last_prob = 0.0
        try:
            peak = float(data.get('max_probability', 0.0))
        except (TypeError, ValueError):
            peak = 0.0
        avg_prob = data.get('average_probability')
        try:
            avg_prob = float(avg_prob) if avg_prob is not None else None
        except (TypeError, ValueError):
            avg_prob = None

        def format_top(entries, label_fn=None):
            formatted = []
            try:
                for key, value in dict(entries).items():
                    formatted.append((str(key), int(value)))
            except Exception:
                formatted = []
            formatted.sort(key=lambda item: item[1], reverse=True)
            formatted = formatted[:5]
            if not formatted:
                return ['  (none)']
            lines = []
            for key, count in formatted:
                label = label_fn(key) if label_fn else key
                lines.append(f"  - {label}: {count}")
            return lines

        def format_pairs(entries):
            formatted = []
            try:
                for key, value in dict(entries).items():
                    formatted.append((str(key), int(value)))
            except Exception:
                formatted = []
            formatted.sort(key=lambda item: item[1], reverse=True)
            formatted = formatted[:5]
            if not formatted:
                return ['  (none)']
            lines = []
            for label, count in formatted:
                display = label.replace('->', ' -> ')
                lines.append(f"  - {display}: {count}")
            return lines

        def format_hourly(entries):
            formatted = []
            if isinstance(entries, dict):
                for key, value in entries.items():
                    try:
                        hour = int(str(key))
                    except ValueError:
                        continue
                    formatted.append((hour % 24, int(value)))
            formatted.sort(key=lambda item: item[0])
            if not formatted:
                return ['  (none)']
            return [f"  - {hour:02d}:00 UTC: {count}" for hour, count in formatted]

        def format_buckets(entries):
            formatted = []
            if isinstance(entries, dict):
                for key, value in entries.items():
                    try:
                        bucket = float(key)
                    except (TypeError, ValueError):
                        continue
                    formatted.append((bucket, int(value)))
            formatted.sort(key=lambda item: item[0])
            if not formatted:
                return ['  (none)']
            return [f"  - {bucket:.1f}: {count}" for bucket, count in formatted]

        def format_length_buckets(entries):
            formatted = []
            if isinstance(entries, dict):
                for key, value in entries.items():
                    try:
                        start = int(str(key).split('-', 1)[0])
                    except Exception:
                        start = 0
                    formatted.append((start, str(key), int(value)))
            formatted.sort(key=lambda item: item[2], reverse=True)
            formatted = formatted[:5]
            if not formatted:
                return ['  (none)']
            return [f"  - {label} B: {count}" for _, label, count in formatted]

        def safe_int(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        def safe_float(value, default=0.0):
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        def format_profiles(entries):
            if not isinstance(entries, dict):
                return ['  (none)']
            processed = []
            for src, profile in entries.items():
                if not isinstance(profile, dict):
                    continue
                risk = safe_float(profile.get('risk_score'), 0.0)
                count = safe_int(profile.get('count'), 0)
                avg_prob = safe_float(profile.get('avg_probability'), 0.0)
                tactic = profile.get('last_tactic') or 'n/a'
                zero_hits = safe_int(profile.get('zero_day_hits'), 0)
                bursts = safe_int(profile.get('burst_count'), 0)
                beacons = safe_int(profile.get('beacon_count'), 0)
                last_seen = profile.get('last_seen', 'unknown')
                proto = profile.get('last_protocol', 'n/a')
                port = profile.get('last_port')
                port_info = f", port {port}" if port is not None else ''
                line = (
                    f"  - {src}: risk {risk:.2f}, alerts {count}, avg {avg_prob:.2f}, "
                    f"tactic {tactic}, zero-day {zero_hits}, bursts {bursts}, "
                    f"beacons {beacons}, last {last_seen}, proto {proto}{port_info}"
                )
                processed.append((risk, line))
            processed.sort(key=lambda item: item[0], reverse=True)
            if not processed:
                return ['  (none)']
            return [entry for _, entry in processed[:5]]

        def build_section(label, formatted):
            if not formatted or formatted == ['  (none)']:
                return [f'  {label}: (none)']
            section_lines = [f'  {label}:']
            for entry in formatted:
                entry = entry.strip()
                if not entry:
                    continue
                section_lines.append(f'    {entry}')
            if len(section_lines) == 1:
                section_lines[0] = f'  {label}: (none)'
            return section_lines

        history = []
        for item in data.get('recent_alerts', []):
            if isinstance(item, dict):
                try:
                    prob_val = float(item.get('probability', 0.0))
                except (TypeError, ValueError):
                    prob_val = 0.0
                history.append({
                    'time': item.get('time', 'unknown'),
                    'src': item.get('src', 'n/a'),
                    'dst': item.get('dst', 'n/a'),
                    'probability': prob_val,
                    'reason': item.get('reason', 'n/a'),
                })

        probabilities = [entry['probability'] for entry in history]
        suggested = None
        if probabilities:
            probs_sorted = sorted(probabilities)
            index = int(round(0.8 * (len(probs_sorted) - 1)))
            index = max(0, min(index, len(probs_sorted) - 1))
            suggested = probs_sorted[index]

        if history:
            recent_lines = [
                f"  - {entry['time']} | {entry['src']} -> {entry['dst']} | {entry['probability']:.3f} | {entry['reason']}"
                for entry in reversed(history[-5:])
            ]
        else:
            recent_lines = ['  (no recent alerts)']

        try:
            stddev = float(data.get('prob_stddev'))
        except (TypeError, ValueError):
            stddev = None

        try:
            min_ttl = int(data.get('min_ttl'))
        except (TypeError, ValueError):
            min_ttl = None

        try:
            avg_length = float(data.get('average_length'))
        except (TypeError, ValueError):
            avg_length = None

        try:
            max_length = int(data.get('max_length'))
        except (TypeError, ValueError):
            max_length = None

        try:
            current_high_streak = int(data.get('current_high_streak', 0))
        except (TypeError, ValueError):
            current_high_streak = 0
        try:
            longest_high_streak = int(data.get('longest_high_streak', 0))
        except (TypeError, ValueError):
            longest_high_streak = 0
        try:
            current_low_streak = int(data.get('current_low_streak', 0))
        except (TypeError, ValueError):
            current_low_streak = 0
        try:
            longest_low_streak = int(data.get('longest_low_streak', 0))
        except (TypeError, ValueError):
            longest_low_streak = 0

        try:
            alerts_current_minute = int(data.get('alerts_current_minute', 0))
        except (TypeError, ValueError):
            alerts_current_minute = 0
        try:
            alerts_last_hour = int(data.get('alerts_last_hour', 0))
        except (TypeError, ValueError):
            alerts_last_hour = 0
        peak_minute = data.get('peak_minute_label')
        try:
            peak_minute_count = int(data.get('peak_minute_count', 0))
        except (TypeError, ValueError):
            peak_minute_count = 0

        recent_minutes = []
        minute_counts = data.get('minute_counts')
        if isinstance(minute_counts, dict):
            for label, value in minute_counts.items():
                try:
                    recent_minutes.append((str(label), int(value)))
                except Exception:
                    continue
        recent_minutes.sort(key=lambda item: item[0], reverse=True)
        recent_minutes = recent_minutes[:5]

        velocity_lines = []
        if total > 0:
            velocity_lines.append(f"  Alerts this minute: {alerts_current_minute}")
            velocity_lines.append(f"  Alerts in last hour: {alerts_last_hour}")
            if peak_minute and peak_minute_count:
                velocity_lines.append(f"  Peak minute: {peak_minute} ({peak_minute_count} alerts)")
            if recent_minutes:
                velocity_lines.append("  Recent minute totals:")
                for label, count in recent_minutes:
                    velocity_lines.append(f"    - {label}: {count}")

        lines = [
            'Neural IDS alert statistics',
            f"  Total alerts: {total}",
            f"  High confidence alerts: {high}",
            f"  Low confidence alerts: {low}",
            f"  Peak probability: {peak:.3f}",
        ]
        if avg_prob is not None:
            lines.append(f"  Average alert probability: {avg_prob:.3f}")
        if stddev is not None:
            lines.append(f"  Probability standard deviation: {stddev:.3f}")
        if suggested is not None:
            lines.append(f"  Suggested threshold (80th percentile): {suggested:.3f}")
        lines.extend([
            f"  Last alert time: {last}",
            f"  Last alert probability: {last_prob:.3f}",
            f"  Last alert reason: {reason}",
            f"  Last packet summary: {summary}",
        ])
        if velocity_lines:
            lines.extend(['', 'Alert velocity:', *velocity_lines])
        lines.extend([
            '',
            'High/low confidence streaks:',
            f"  Current high-confidence streak: {current_high_streak}",
            f"  Longest high-confidence streak: {longest_high_streak}",
            f"  Current low-confidence streak: {current_low_streak}",
            f"  Longest low-confidence streak: {longest_low_streak}",
            '',
            'Top source IPs:',
            *format_top(data.get('sources', {})),
            '',
            'Source address categories:',
            *format_top(data.get('source_categories', {})),
            '',
            'Source IP versions:',
            *format_top(data.get('source_versions', {})),
            '',
            'Top source subnets:',
            *format_top(data.get('source_subnets', {})),
            '',
            'Top destination IPs:',
            *format_top(data.get('destinations', {})),
            '',
            'Destination address categories:',
            *format_top(data.get('destination_categories', {})),
            '',
            'Destination IP versions:',
            *format_top(data.get('destination_versions', {})),
            '',
            'Top destination subnets:',
            *format_top(data.get('destination_subnets', {})),
            '',
            'Top destination ports:',
            *format_top(data.get('destination_ports', {})),
            '',
            'Protocol distribution:',
            *format_top(data.get('protocols', {})),
            '',
            'TTL distribution:',
            *format_top(data.get('ttl_distribution', {}), lambda key: f'TTL {key}'),
        ])
        if min_ttl is not None:
            lines.append(f"  Lowest observed TTL: {min_ttl}")
        lines.extend([
            '',
            'Packet length buckets:',
            *format_length_buckets(data.get('length_buckets', {})),
        ])
        if avg_length is not None:
            lines.append(f"  Average packet length: {avg_length:.1f} B")
        if max_length is not None:
            lines.append(f"  Maximum packet length: {max_length} B")
        lines.extend([
            '',
            'TCP flag combinations:',
            *format_top(data.get('tcp_flag_combinations', {})),
            '',
            'Frequent alert reasons:',
            *format_top(data.get('reason_counts', {})),
            '',
            'Common source → destination pairs:',
            *format_pairs(data.get('source_destination_pairs', {})),
            '',
            'Hourly alert timeline:',
            *format_hourly(data.get('hourly_distribution', {})),
            '',
            'Probability distribution (0.1 buckets):',
            *format_buckets(data.get('probability_buckets', {})),
        ])
        zero_day_total = safe_int(data.get('zero_day_alerts', 0))
        zero_day_sources = format_top(data.get('zero_day_sources', {}))
        tactic_lines = format_top(data.get('tactic_counts', {}))
        technique_lines = format_top(data.get('technique_counts', {}))
        profile_lines = format_profiles(data.get('source_profiles', {}))
        burst_lines = format_top(data.get('burst_sources', {}))
        beacon_lines = format_top(data.get('beacon_sources', {}))
        anomaly_lines = format_top(data.get('protocol_anomalies', {}))
        progression_lines = format_top(data.get('kill_chain_progressions', {}))
        transition_lines = format_top(data.get('tactic_transitions', {}))
        diversity_lines = format_top(data.get('tactic_diversity_sources', {}))
        dwell_lines = format_top(data.get('long_dwell_sources', {}))
        apt_lines = format_top(data.get('apt_suspects', {}))
        stage_lines = format_top(
            data.get('tactic_stage_totals', {}),
            lambda label: label.split('-', 1)[1] if '-' in label else label,
        )

        lines.extend([
            '',
            'Next-generation insights:',
            f'  Zero-day anomaly alerts: {zero_day_total}',
        ])
        lines.extend(build_section('Zero-day source leaders', zero_day_sources))
        lines.extend(build_section('MITRE tactic leaders', tactic_lines))
        lines.extend(build_section('Technique leaders', technique_lines))
        lines.extend(build_section('High-risk sources', profile_lines))
        lines.extend(build_section('Bursting sources', burst_lines))
        lines.extend(build_section('Beaconing sources', beacon_lines))
        lines.extend(build_section('Protocol anomalies', anomaly_lines))
        lines.extend(build_section('Kill-chain stage totals', stage_lines))
        lines.extend(build_section('Kill-chain progressions', progression_lines))
        lines.extend(build_section('Frequent tactic transitions', transition_lines))
        lines.extend(build_section('Multi-tactic sources', diversity_lines))
        lines.extend(build_section('Long-dwell sources (minutes observed)', dwell_lines))
        lines.extend(build_section('APT suspect watchlist', apt_lines))

        lines.extend([
            '',
            'Recent alerts (newest first):',
            *recent_lines,
        ])
        print('\n'.join(lines))
PY
    if [ "$USE_DIALOG" -eq 1 ]; then
        dialog --backtitle "Kali IDS" --title "Alert Statistics" --textbox "$tmp" 22 90
    else
        cat "$tmp"
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
}

show_nextgen_insights() {
    local tmp
    tmp=$(mktemp)
    python3 - <<'PY' >"$tmp" 2>/dev/null
import json
import pathlib


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


path = pathlib.Path('/var/lib/nn_ids/alert_stats.json')
if not path.exists():
    print('No alerts have been recorded yet.')
else:
    try:
        data = json.loads(path.read_text() or '{}')
    except json.JSONDecodeError:
        print('Alert statistics are unavailable (corrupted data).')
    else:
        lines = ['Next-generation threat intelligence summary:']

        zero_day = safe_int(data.get('zero_day_alerts', 0))
        lines.append(f"- Zero-day anomalies detected: {zero_day}")

        tactic_counts = data.get('tactic_counts') or {}
        if isinstance(tactic_counts, dict) and tactic_counts:
            top_tactic = max(
                tactic_counts.items(), key=lambda item: safe_int(item[1])
            )
            lines.append(
                f"- Dominant tactic: {top_tactic[0]} ({safe_int(top_tactic[1])} alerts)"
            )
        else:
            lines.append("- Dominant tactic: none recorded yet")

        technique_counts = data.get('technique_counts') or {}
        if isinstance(technique_counts, dict) and technique_counts:
            top_technique = max(
                technique_counts.items(), key=lambda item: safe_int(item[1])
            )
            lines.append(
                f"- Most frequent technique: {top_technique[0]} ({safe_int(top_technique[1])} alerts)"
            )
        else:
            lines.append("- Most frequent technique: none recorded yet")

        zero_sources = data.get('zero_day_sources') or {}
        if isinstance(zero_sources, dict) and zero_sources:
            lines.append("- Zero-day source hotspots:")
            for src, count in sorted(
                zero_sources.items(),
                key=lambda item: safe_int(item[1]),
                reverse=True,
            )[:3]:
                lines.append(f"  * {src} ({safe_int(count)} anomalies)")

        profiles = data.get('source_profiles') or {}
        high_risk = []
        if isinstance(profiles, dict):
            for src, profile in profiles.items():
                if not isinstance(profile, dict):
                    continue
                risk = safe_float(profile.get('risk_score'), 0.0)
                count = safe_int(profile.get('count'), 0)
                tactic = profile.get('last_tactic') or 'n/a'
                last_seen = profile.get('last_seen', 'unknown')
                high_risk.append(
                    (
                        risk,
                        f"  * {src} (risk {risk:.2f}, alerts {count}, tactic {tactic}, last seen {last_seen})",
                    )
                )
        high_risk.sort(key=lambda item: item[0], reverse=True)
        if high_risk:
            lines.append("- High-risk sources:")
            for _, entry in high_risk[:3]:
                lines.append(entry)
        else:
            lines.append("- High-risk sources: none recorded yet")

        def describe_watchlist(label, payload):
            if not isinstance(payload, dict) or not payload:
                lines.append(f"- {label}: none observed")
                return False
            lines.append(f"- {label}:")
            for src, count in sorted(
                payload.items(),
                key=lambda item: safe_int(item[1]),
                reverse=True,
            )[:3]:
                lines.append(f"  * {src} ({safe_int(count)} events)")
            return True


        burst_flag = describe_watchlist('Bursting sources', data.get('burst_sources'))
        beacon_flag = describe_watchlist('Beaconing sources', data.get('beacon_sources'))

        stage_totals = data.get('tactic_stage_totals') or {}
        if isinstance(stage_totals, dict) and stage_totals:
            top_stage = max(
                stage_totals.items(), key=lambda item: safe_int(item[1])
            )
            stage_label = top_stage[0]
            if '-' in stage_label:
                stage_label = stage_label.split('-', 1)[1]
            lines.append(
                f"- Kill-chain focus: {stage_label} ({safe_int(top_stage[1])} alerts)"
            )
        else:
            lines.append("- Kill-chain focus: none recorded yet")

        progressions = data.get('kill_chain_progressions') or {}
        progression_flag = False
        if isinstance(progressions, dict) and progressions:
            lines.append('- Kill-chain progression hotspots:')
            for src, count in sorted(
                progressions.items(),
                key=lambda item: safe_int(item[1]),
                reverse=True,
            )[:3]:
                lines.append(f"  * {src} ({safe_int(count)} stage jumps)")
            progression_flag = True
        else:
            lines.append('- Kill-chain progression hotspots: none observed')

        transitions = data.get('tactic_transitions') or {}
        if isinstance(transitions, dict) and transitions:
            lines.append('- Frequent tactic transitions:')
            for combo, count in sorted(
                transitions.items(),
                key=lambda item: safe_int(item[1]),
                reverse=True,
            )[:3]:
                lines.append(f"  * {combo}: {safe_int(count)} occurrences")
        else:
            lines.append('- Frequent tactic transitions: none observed')

        diversity = data.get('tactic_diversity_sources') or {}
        if isinstance(diversity, dict) and diversity:
            top_diverse = max(
                diversity.items(), key=lambda item: safe_int(item[1])
            )
            lines.append(
                f"- Most versatile source: {top_diverse[0]} ({safe_int(top_diverse[1])} unique tactics)"
            )
        else:
            lines.append('- Most versatile source: none recorded yet')

        dwellers = data.get('long_dwell_sources') or {}
        dwell_flag = False
        if isinstance(dwellers, dict) and dwellers:
            lines.append('- Long-dwell sources (minutes observed):')
            for src, minutes in sorted(
                dwellers.items(),
                key=lambda item: safe_int(item[1]),
                reverse=True,
            )[:3]:
                lines.append(f"  * {src} ({safe_int(minutes)} minutes)")
            dwell_flag = True
        else:
            lines.append('- Long-dwell sources: none observed')

        apt_suspects = data.get('apt_suspects') or {}
        apt_flag = False
        if isinstance(apt_suspects, dict) and apt_suspects:
            lines.append('- APT suspect watchlist:')
            for src, stages in sorted(
                apt_suspects.items(),
                key=lambda item: safe_int(item[1]),
                reverse=True,
            )[:3]:
                lines.append(f"  * {src} ({safe_int(stages)} kill-chain advancements)")
            apt_flag = True
        else:
            lines.append('- APT suspect watchlist: none flagged')

        anomalies = data.get('protocol_anomalies') or {}
        if isinstance(anomalies, dict) and anomalies:
            lines.append('- Protocol anomalies:')
            for proto, count in sorted(
                anomalies.items(),
                key=lambda item: safe_int(item[1]),
                reverse=True,
            )[:5]:
                lines.append(f"  * {proto}: {safe_int(count)} alerts")
        else:
            lines.append('- Protocol anomalies: none observed')

        recommendations = []
        if zero_day > 0:
            recommendations.append(
                "Escalate zero-day anomalies and capture supporting packets."
            )
        if high_risk[:1]:
            recommendations.append(
                "Consider adding the highest-risk sources to containment or blocklists."
            )
        if burst_flag:
            recommendations.append(
                "Run network discovery to validate targets hit by burst activity."
            )
        if beacon_flag:
            recommendations.append(
                "Inspect potential beaconing hosts for command-and-control indicators."
            )
        if progression_flag:
            recommendations.append(
                'Trace kill-chain progression hosts for lateral movement evidence.'
            )
        if dwell_flag:
            recommendations.append(
                'Audit long-dwell sources for persistence or backdoor activity.'
            )
        if apt_flag:
            recommendations.append(
                'Initiate incident response for multi-stage APT-suspect actors.'
            )
        if recommendations:
            lines.append('')
            lines.append('Recommended actions:')
            for item in recommendations:
                lines.append(f"  - {item}")

        print('\n'.join(lines))
PY
    if [ "$USE_DIALOG" -eq 1 ]; then
        dialog --backtitle "Kali IDS" --title "Next-gen Insights" --textbox "$tmp" 22 90
    else
        cat "$tmp"
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
}

reset_alert_stats() {
    local stats_file="/var/lib/nn_ids/alert_stats.json"
    if [ "$USE_DIALOG" -eq 1 ]; then
        dialog --yesno "Reset aggregated alert statistics?" 6 50 || return
    else
        read -rp "Reset aggregated alert statistics? (y/N): " ans
        case "$ans" in
            [Yy]*) ;;
            *) echo "Aborted."; return ;;
        esac
    fi
    rm -f "$stats_file"
    show_msg "Alert statistics reset"
}

show_alert_history() {
    local tmp
    tmp=$(mktemp)
    python3 - <<'PY' >"$tmp" 2>/dev/null
import json
import pathlib

path = pathlib.Path('/var/lib/nn_ids/alert_stats.json')
if not path.exists():
    print('No alerts have been recorded yet.')
else:
    try:
        data = json.loads(path.read_text() or '{}')
    except json.JSONDecodeError:
        print('Alert statistics are unavailable (corrupted data).')
    else:
        history = []
        for item in data.get('recent_alerts', []):
            if isinstance(item, dict):
                try:
                    prob_val = float(item.get('probability', 0.0))
                except (TypeError, ValueError):
                    prob_val = 0.0
                history.append(
                    (
                        item.get('time', 'unknown'),
                        item.get('src', 'n/a'),
                        item.get('dst', 'n/a'),
                        prob_val,
                        item.get('reason', 'n/a'),
                    )
                )
        if not history:
            print('No alert history recorded yet.')
        else:
            lines = ['Recent neural IDS alerts (newest first):']
            for entry in reversed(history[-10:]):
                ts, src, dst, prob, reason = entry
                lines.append(f"  - {ts} | {src} -> {dst} | {prob:.3f} | {reason}")
            print('\n'.join(lines))
PY
    if [ "$USE_DIALOG" -eq 1 ]; then
        dialog --backtitle "Kali IDS" --title "Alert History" --textbox "$tmp" 22 90
    else
        cat "$tmp"
        read -rp "Press enter to continue" _
    fi
    rm -f "$tmp"
}

export_alert_stats() {
    local stats_file="/var/lib/nn_ids/alert_stats.json"
    if [ ! -f "$stats_file" ]; then
        show_msg "No alert statistics are available to export"
        return
    fi
    local default_path="$PWD/nn_ids_alert_stats.json"
    local dest
    if [ "$USE_DIALOG" -eq 1 ]; then
        dest=$(dialog --inputbox "Export analytics snapshot to:" 9 70 "$default_path" 3>&1 1>&2 2>&3) || return
    else
        read -rp "Export analytics snapshot to [$default_path]: " dest
        dest=${dest:-$default_path}
    fi
    dest=${dest:-$default_path}
    local dir
    dir=$(dirname "$dest")
    if ! mkdir -p "$dir" 2>/dev/null; then
        show_msg "Unable to create destination directory: $dir"
        return
    fi
    if cp "$stats_file" "$dest" 2>/dev/null; then
        show_msg "Alert analytics exported to $dest"
    else
        show_msg "Failed to export analytics to $dest"
    fi
}

alert_analytics_menu() {
    while true; do
        local choice
        if [ "$USE_DIALOG" -eq 1 ]; then
            choice=$(dialog --backtitle "Kali IDS" --title "Alert Analytics" --menu "Select an action:" 18 74 7 \
                1 "View aggregated statistics" \
                2 "View recent alert history" \
                3 "View next-gen threat insights" \
                4 "Export analytics snapshot" \
                5 "Reset alert statistics" \
                6 "Return" 3>&1 1>&2 2>&3) || break
        else
            echo "Alert analytics tools:"
            echo "1) View aggregated statistics"
            echo "2) View recent alert history"
            echo "3) View next-gen threat insights"
            echo "4) Export analytics snapshot"
            echo "5) Reset alert statistics"
            echo "6) Return"
            read -rp "Choose an option: " choice
        fi
        case "$choice" in
            1)
                show_alert_stats
                ;;
            2)
                show_alert_history
                ;;
            3)
                show_nextgen_insights
                ;;
            4)
                export_alert_stats
                ;;
            5)
                reset_alert_stats
                ;;
            6)
                break
                ;;
            *)
                [ "$USE_DIALOG" -eq 1 ] || echo "Invalid option"
                ;;
        esac
    done
}

configure_thresholds() {
    while true; do
        local ids proc risk sys window choice
        ids=$(get_value NN_IDS_THRESHOLD)
        proc=$(get_value GA_PROC_THRESHOLD)
        risk=$(get_value GA_PROC_MIN_RISK)
        sys=$(get_value NN_SYS_THRESHOLD)
        window=$(get_value NN_SYS_WINDOW)
        if [ "$USE_DIALOG" -eq 1 ]; then
            choice=$(dialog --backtitle "Kali IDS" --title "Detection Thresholds" --menu "Adjust alert thresholds:" 20 70 6 \
                1 "IDS probability threshold [$ids]" \
                2 "GA Tech process probability threshold [$proc]" \
                3 "GA Tech process risk threshold [$risk]" \
                4 "GA Tech syscall probability threshold [$sys]" \
                5 "GA Tech syscall window size [$window]" \
                6 "Return" 3>&1 1>&2 2>&3) || break
        else
            echo "Detection threshold settings:"
            echo " 1) IDS probability threshold (current: $ids)"
            echo " 2) GA Tech process probability threshold (current: $proc)"
            echo " 3) GA Tech process risk threshold (current: $risk)"
            echo " 4) GA Tech syscall probability threshold (current: $sys)"
            echo " 5) GA Tech syscall window size (current: $window)"
            echo " 6) Return"
            read -rp "Choose: " choice
        fi
        case "$choice" in
            1) prompt_float_value "NN_IDS_THRESHOLD" "Set IDS alert probability" 0 1 || true ;;
            2) prompt_float_value "GA_PROC_THRESHOLD" "Set GA Tech process probability" 0 1 || true ;;
            3) prompt_float_value "GA_PROC_MIN_RISK" "Set GA Tech process risk threshold" 0 1 || true ;;
            4) prompt_float_value "NN_SYS_THRESHOLD" "Set GA Tech syscall probability" 0 1 || true ;;
            5) prompt_int_value "NN_SYS_WINDOW" "Set GA Tech syscall window size" 1 500 || true ;;
            6) break ;;
            *) show_msg "Invalid option" ;;
        esac
    done
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
        choice=$(dialog --clear --colors --backtitle "Kali IDS" --title "IDS Dashboard" --menu "Select an option:" 20 75 35 \
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
            34 "Run GA Tech process scan" \
            35 "Retrain GA Tech process model" \
            36 "View GA Tech process training log" \
            37 "Monitor GA Tech process activity" \
            38 "Summarize GA Tech process detections" \
            39 "Refresh GA Tech baseline inventory" \
            40 "View GA Tech system call alerts" \
            41 "View GA Tech system call training log" \
            42 "Monitor GA Tech system call activity" \
            43 "Summarize GA Tech system call detections" \
            44 "Retrain GA Tech system call model" \
            45 "Configure detection thresholds" \
            46 "View alert statistics" \
            47 "Alert analytics tools" \
            48 "Exit" 3>&1 1>&2 2>&3) || break
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
        echo -e "${GREEN}34)${RESET} Run GA Tech process scan"
        echo -e "${GREEN}35)${RESET} Retrain GA Tech process model"
        echo -e "${GREEN}36)${RESET} View GA Tech process training log"
        echo -e "${GREEN}37)${RESET} Monitor GA Tech process activity"
        echo -e "${GREEN}38)${RESET} Summarize GA Tech process detections"
        echo -e "${GREEN}39)${RESET} Refresh GA Tech baseline inventory"
        echo -e "${GREEN}40)${RESET} View GA Tech system call alerts"
        echo -e "${GREEN}41)${RESET} View GA Tech system call training log"
        echo -e "${GREEN}42)${RESET} Monitor GA Tech system call activity"
        echo -e "${GREEN}43)${RESET} Summarize GA Tech system call detections"
        echo -e "${GREEN}44)${RESET} Retrain GA Tech system call model"
        echo -e "${GREEN}45)${RESET} Configure detection thresholds"
        echo -e "${GREEN}46)${RESET} View alert statistics"
        echo -e "${GREEN}47)${RESET} Alert analytics tools"
        echo -e "${GREEN}48)${RESET} Exit"
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
            run_ga_process_scan
            ;;
        35)
            retrain_ga_process_model
            ;;
        36)
            view_ga_train_log
            ;;
        37)
            monitor_ga_processes
            ;;
        38)
            summarize_ga_process_history
            ;;
        39)
            refresh_ga_process_baseline
            ;;
        40)
            view_ga_sys_alerts
            ;;
        41)
            view_ga_sys_train_log
            ;;
        42)
            monitor_ga_syscalls
            ;;
        43)
            summarize_ga_sys_detections
            ;;
        44)
            retrain_ga_sys_model
            ;;
        45)
            configure_thresholds
            ;;
        46)
            show_alert_stats
            ;;
        47)
            alert_analytics_menu
            ;;
        48)
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
