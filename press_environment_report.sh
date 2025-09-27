#!/bin/bash
# press_environment_report.sh - Capture environment details before running the press
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: press_environment_report.sh [-o output_path]

Generate a Markdown report describing the current host environment (OS, CPU, memory,
disk, network, critical service status, and tooling availability). The report is saved
to the specified path or to ./press_environment_<timestamp>.md by default and echoed
to stdout.
USAGE
}

OUTPUT=""
while getopts "o:h" opt; do
    case "$opt" in
        o) OUTPUT=$OPTARG ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

timestamp=$(date +%Y%m%d_%H%M%S)
if [[ -z "$OUTPUT" ]]; then
    OUTPUT="$(pwd)/press_environment_${timestamp}.md"
fi
mkdir -p "$(dirname "$OUTPUT")"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

report_datetime=$(date -u +"%Y-%m-%d %H:%M:%SZ")
hostname_fqdn=$(hostname -f 2>/dev/null || hostname)

declare -a warnings=()
declare -A warning_seen=()
add_warning() {
    local message="$1"
    if [[ -z "${warning_seen[$message]+x}" ]]; then
        warnings+=("$message")
        warning_seen[$message]=1
    fi
}

normalize_field() {
    local value="$1"
    value=${value//$'\r'/ }
    value=${value//$'\n'/ }
    value=${value//$'\t'/ }
    while [[ "$value" == *"  "* ]]; do
        value=${value//  / }
    done
    value="${value#${value%%[![:space:]]*}}"
    value="${value%${value##*[![:space:]]}}"
    printf '%s' "$value"
}

format_duration() {
    local total_seconds="$1"
    if [[ -z "$total_seconds" || ! "$total_seconds" =~ ^[0-9]+$ ]]; then
        printf ''
        return
    fi
    local days=$(( total_seconds / 86400 ))
    local hours=$(( (total_seconds % 86400) / 3600 ))
    local minutes=$(( (total_seconds % 3600) / 60 ))
    local seconds=$(( total_seconds % 60 ))
    local parts=()
    if (( days > 0 )); then
        parts+=("${days}d")
    fi
    if (( hours > 0 )); then
        parts+=("${hours}h")
    fi
    if (( minutes > 0 )); then
        parts+=("${minutes}m")
    fi
    if (( ${#parts[@]} == 0 )); then
        parts+=("${seconds}s")
    elif (( seconds > 0 )); then
        parts+=("${seconds}s")
    fi
    printf '%s' "${parts[*]}"
}

virt_systemd="systemd-detect-virt: unavailable"
virt_what_available=false
virt_what_lines=()
container_runtime="none detected"
container_hints=()

apt_upgrade_count="unavailable"
apt_security_count="unavailable"
apt_upgrade_lines=()
apt_last_update="unknown"
apt_last_update_age=""
reboot_required=false
top_cpu_output=""
top_mem_output=""

if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt_value=$(systemd-detect-virt 2>/dev/null || true)
    if [[ -n "$virt_value" ]]; then
        virt_systemd="systemd-detect-virt: $virt_value"
    else
        virt_systemd="systemd-detect-virt: none detected"
    fi

    container_value=$(systemd-detect-virt --container 2>/dev/null || true)
    if [[ -n "$container_value" && "$container_value" != "none" ]]; then
        container_runtime="$container_value (detected by systemd-detect-virt)"
    fi
fi

if command -v virt-what >/dev/null 2>&1; then
    virt_what_available=true
    while IFS= read -r line; do
        virt_what_lines+=("$line")
    done < <(virt-what 2>/dev/null || true)
fi

if [[ "$container_runtime" == "none detected" && -f /proc/1/cgroup ]]; then
    cgroup_hint=$(grep -Eo '(docker|lxc|podman|containerd|kubepods)' /proc/1/cgroup 2>/dev/null | head -n1 || true)
    if [[ -n "$cgroup_hint" ]]; then
        container_runtime="$cgroup_hint (identified via /proc/1/cgroup)"
    fi
fi

for runtime_cli in docker podman containerd nerdctl crictl; do
    if command -v "$runtime_cli" >/dev/null 2>&1; then
        container_hints+=("$runtime_cli CLI available")
    fi
done

if command -v apt-get >/dev/null 2>&1; then
    apt_upgrade_count=0
    apt_security_count=0
    apt_upgrade_lines=()
    apt_simulated_output=$(DEBIAN_FRONTEND=noninteractive apt-get -s upgrade 2>/dev/null || true)
    if [[ -n "$apt_simulated_output" ]]; then
        while IFS= read -r line; do
            line=${line#Inst }
            [[ -z "$line" ]] && continue
            apt_upgrade_lines+=("$line")
        done < <(printf '%s\n' "$apt_simulated_output" | grep '^Inst ' || true)
        apt_upgrade_count=${#apt_upgrade_lines[@]}
        if (( apt_upgrade_count > 0 )); then
            for detail in "${apt_upgrade_lines[@]}"; do
                if [[ "${detail,,}" == *security* ]]; then
                    ((apt_security_count++))
                fi
            done
        fi
    fi
    if (( apt_upgrade_count > 0 )); then
        add_warning "Pending APT upgrades detected (${apt_upgrade_count})"
    fi
    if (( apt_security_count > 0 )); then
        add_warning "Security updates pending (${apt_security_count})"
    fi
    apt_last_update_stamp="/var/lib/apt/periodic/update-success-stamp"
    if [[ -f "$apt_last_update_stamp" ]]; then
        stamp_epoch=$(stat -c %Y "$apt_last_update_stamp" 2>/dev/null || echo "")
        if [[ -n "$stamp_epoch" && "$stamp_epoch" =~ ^[0-9]+$ ]]; then
            apt_last_update=$(date -u -d "@$stamp_epoch" +"%Y-%m-%d %H:%M:%SZ" 2>/dev/null || echo "unknown")
            now_epoch=$(date +%s)
            if [[ "$now_epoch" =~ ^[0-9]+$ ]]; then
                diff=$(( now_epoch - stamp_epoch ))
                apt_last_update_age=$(format_duration "$diff")
            fi
        fi
    fi
else
    apt_upgrade_count="unavailable"
    apt_security_count="unavailable"
fi

if [[ -f /var/run/reboot-required ]]; then
    reboot_required=true
    add_warning "System reboot required before press"
fi

apparmor_state="unavailable"
if [[ -f /sys/module/apparmor/parameters/enabled ]]; then
    read -r aa_value < /sys/module/apparmor/parameters/enabled
    case "$aa_value" in
        Y|y|Y*|y*)
            apparmor_state="enabled"
            ;;
        enforce*|complain*)
            apparmor_state="$aa_value"
            [[ "$aa_value" != enforce* ]] && add_warning "AppArmor not enforcing (value: ${aa_value})"
            ;;
        *)
            apparmor_state="disabled (${aa_value})"
            add_warning "AppArmor is not enforcing (value: ${aa_value})"
            ;;
    esac
else
    add_warning "AppArmor kernel module not detected"
fi

selinux_state="unavailable"
if command -v selinuxenabled >/dev/null 2>&1; then
    if selinuxenabled 2>/dev/null; then
        selinux_state="enabled"
    else
        selinux_state="disabled"
        add_warning "SELinux is disabled"
    fi
elif command -v sestatus >/dev/null 2>&1; then
    selinux_state=$(sestatus 2>/dev/null | awk -F: '/status/ {gsub(/^[ \t]+/,"",$2); print tolower($2)}' | head -n1 || echo unavailable)
    if [[ "$selinux_state" != "enforcing" && "$selinux_state" != "permissive" ]]; then
        add_warning "SELinux not enforcing (status: ${selinux_state:-unknown})"
    fi
fi

declare -A sysctl_expectations=(
    [kernel.kptr_restrict]=1
    [kernel.dmesg_restrict]=1
    [kernel.unprivileged_bpf_disabled]=1
    [kernel.unprivileged_userns_clone]=0
    [fs.protected_hardlinks]=1
    [fs.protected_symlinks]=1
)
declare -a sysctl_statuses=()
for key in "${!sysctl_expectations[@]}"; do
    value=$(sysctl -n "$key" 2>/dev/null || echo "unavailable")
    sysctl_statuses+=("$key|$value|${sysctl_expectations[$key]}")
    if [[ "$value" == "unavailable" ]]; then
        add_warning "sysctl ${key} unavailable"
    elif [[ "$value" != "${sysctl_expectations[$key]}" ]]; then
        add_warning "sysctl ${key} is ${value} (expected ${sysctl_expectations[$key]})"
    fi
done

declare -a unit_statuses=()
declare -a timer_statuses=()
systemctl_ready=false
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files >/dev/null 2>&1; then
        systemctl_ready=true
    else
        add_warning "systemctl present but systemd is not active; skipping unit inspection"
    fi
else
    add_warning "systemctl unavailable; unable to inspect unit status"
fi

if $systemctl_ready; then
    critical_units=(
        nn_ids.service
        nn_ids_capture.service
        nn_ids_retrain.service
        nn_ids_autoblock.service
        nn_ids_report.service
        nn_ids_resource_monitor.service
        nn_ids_healthcheck.service
        nn_ids_sanitize.service
        nn_ids_snapshot.service
        nn_ids_restore.service
        nn_syscall_monitor.service
        process_monitor.service
        port_socket_monitor.service
        threat_feed_blocklist.service
        anti_wipe_monitor.service
        internet_access_monitor.service
    )
    for unit in "${critical_units[@]}"; do
        enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo "missing")
        active=$(systemctl is-active "$unit" 2>/dev/null || echo "inactive")
        enabled=$(normalize_field "$enabled")
        active=$(normalize_field "$active")
        if [[ "$enabled" == *"not-found"* ]]; then
            enabled="missing"
        fi
        unit_statuses+=("$unit|$enabled|$active")
        if [[ "$enabled" != "enabled" ]]; then
            add_warning "Service ${unit} is not enabled (status: ${enabled})"
        fi
        if [[ "$active" != "active" ]]; then
            add_warning "Service ${unit} is not active (status: ${active})"
        fi
    done

    critical_timers=(
        nn_ids_capture.timer
        nn_ids_retrain.timer
        nn_ids_autoblock.timer
        nn_ids_report.timer
        nn_ids_resource_monitor.timer
        nn_ids_sanitize.timer
        nn_ids_snapshot.timer
        nn_ids_restore.timer
        process_monitor.timer
        threat_feed_blocklist.timer
        nn_syscall_monitor.timer
        internet_access_monitor.timer
    )
    for timer in "${critical_timers[@]}"; do
        enabled=$(systemctl is-enabled "$timer" 2>/dev/null || echo "missing")
        active=$(systemctl is-active "$timer" 2>/dev/null || echo "inactive")
        enabled=$(normalize_field "$enabled")
        active=$(normalize_field "$active")
        if [[ "$enabled" == *"not-found"* ]]; then
            enabled="missing"
        fi
        timer_statuses+=("$timer|$enabled|$active")
        if [[ "$enabled" != "enabled" ]]; then
            add_warning "Timer ${timer} is not enabled (status: ${enabled})"
        fi
        if [[ "$active" != "active" ]]; then
            add_warning "Timer ${timer} is not active (status: ${active})"
        fi
    done
fi

declare -a tool_statuses=()
tools=(curl gpg mkisofs isohybrid dialog nmap netdiscover arp-scan nbtscan dnsrecon whatweb enum4linux nikto sslscan snmpwalk masscan traceroute git python3 pip3 shellcheck flake8 bandit black codespell gitleaks isort pre-commit)
for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        tool_statuses+=("$tool|available")
    else
        tool_statuses+=("$tool|missing")
        add_warning "Tool ${tool} is missing"
    fi
done

if command -v ps >/dev/null 2>&1; then
    top_cpu_output=$(ps -eo pid,comm,%cpu --sort=-%cpu 2>/dev/null | head -n 6 || true)
    top_mem_output=$(ps -eo pid,comm,%mem --sort=-%mem 2>/dev/null | head -n 6 || true)
fi

{
    echo "# Press Environment Report"
    echo ""
    echo "- Generated (UTC): ${report_datetime}"
    echo "- Hostname: ${hostname_fqdn}"
    echo "- Working directory: $(pwd)"
    echo ""
    echo "## Summary"
    if (( ${#warnings[@]} == 0 )); then
        echo "- No warnings detected."
    else
        echo "- Detected warnings:"
        for warning in "${warnings[@]}"; do
            echo "  - ${warning}"
        done
    fi
    echo ""
    echo "## OS Release"
    if command -v lsb_release >/dev/null 2>&1; then
        lsb_release -a 2>/dev/null
    elif [[ -f /etc/os-release ]]; then
        cat /etc/os-release
    else
        uname -a
    fi
    echo ""
    echo "## Kernel & Architecture"
    uname -a
    echo "Architecture: $(uname -m)"
    echo ""
    echo "## Virtualization & Containers"
    echo "$virt_systemd"
    if $virt_what_available; then
        if (( ${#virt_what_lines[@]} > 0 )); then
            echo "virt-what:" 
            for line in "${virt_what_lines[@]}"; do
                echo "  $line"
            done
        else
            echo "virt-what: none detected"
        fi
    else
        echo "virt-what: unavailable"
    fi
    echo "Container runtime: ${container_runtime}"
    if (( ${#container_hints[@]} > 0 )); then
        echo "Container tooling:"
        for hint in "${container_hints[@]}"; do
            echo "- $hint"
        done
    fi
    echo ""
    echo "## CPU"
    if command -v lscpu >/dev/null 2>&1; then
        lscpu
    elif [[ -f /proc/cpuinfo ]]; then
        grep -m1 'model name' /proc/cpuinfo || true
        echo "Logical CPUs: $(nproc 2>/dev/null || echo unknown)"
    else
        echo "CPU information unavailable"
    fi
    echo ""
    echo "## Memory"
    if command -v free >/dev/null 2>&1; then
        free -h
    elif [[ -f /proc/meminfo ]]; then
        cat /proc/meminfo
    else
        echo "Memory information unavailable"
    fi
    echo ""
    echo "## Disk Usage"
    df -h /
    echo ""
    echo "Working directory usage:"
    df -h "$(pwd)"
    echo ""
    echo "## Package maintenance"
    if [[ "$apt_upgrade_count" == "unavailable" ]]; then
        echo "- APT tooling unavailable; skipping upgrade inspection."
    else
        echo "- Pending upgrades: ${apt_upgrade_count}"
        echo "- Pending security upgrades: ${apt_security_count}"
        if [[ -n "$apt_last_update" && "$apt_last_update" != "unknown" ]]; then
            if [[ -n "$apt_last_update_age" ]]; then
                echo "- Last apt update: ${apt_last_update} (age: ${apt_last_update_age})"
            else
                echo "- Last apt update: ${apt_last_update}"
            fi
        fi
        if $reboot_required; then
            echo "- Reboot required: yes"
        else
            echo "- Reboot required: no"
        fi
        if (( ${#apt_upgrade_lines[@]} > 0 )); then
            echo ""
            echo "Upgradable packages (sample):"
            count=0
            for entry in "${apt_upgrade_lines[@]}"; do
                printf '  - %s\n' "$entry"
                (( count++ >= 14 )) && break
            done
            if (( ${#apt_upgrade_lines[@]} > 15 )); then
                remaining=$(( ${#apt_upgrade_lines[@]} - 15 ))
                echo "  - ... (${remaining} more packages)"
            fi
        fi
    fi
    echo ""
    if command -v lsblk >/dev/null 2>&1; then
        echo "Block devices:"
        lsblk -o NAME,FSTYPE,SIZE,TYPE,MOUNTPOINT
        echo ""
    fi
    echo "## Network Interfaces"
    if command -v ip >/dev/null 2>&1; then
        ip -brief address || ip addr show
        echo ""
        echo "Default routes:"
        ip route show default || true
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig -a
    else
        echo "No network tooling (ip/ifconfig) available."
    fi
    echo ""
    echo "Connectivity probes:"
    if command -v curl >/dev/null 2>&1; then
        for url in https://kali.org https://google.com; do
            if curl -fs --head "$url" >/dev/null 2>&1; then
                echo "- $url reachable"
            else
                echo "- $url unreachable"
            fi
        done
    else
        echo "curl unavailable; skipping HTTP probes"
    fi
    echo ""
    echo "## Listening sockets (top 25)"
    if command -v ss >/dev/null 2>&1; then
        ss -H -tulpn 2>/dev/null | head -n 25 || echo "Unable to enumerate sockets"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn 2>/dev/null | head -n 25 || echo "Unable to enumerate sockets"
    else
        echo "No ss/netstat available; skipping socket listing."
    fi
    echo ""
    if [[ -n "$top_cpu_output" || -n "$top_mem_output" ]]; then
        echo "## Top resource consumers"
        if [[ -n "$top_cpu_output" ]]; then
            echo "Top CPU processes:"
            printf '```\n'
            echo "$top_cpu_output"
            printf '```\n'
        else
            echo "Top CPU processes: unavailable"
        fi
        echo ""
        if [[ -n "$top_mem_output" ]]; then
            echo "Top memory processes:"
            printf '```\n'
            echo "$top_mem_output"
            printf '```\n'
        else
            echo "Top memory processes: unavailable"
        fi
        echo ""
    fi
    echo "## Security Modules & Kernel Hardening"
    echo "AppArmor: ${apparmor_state}"
    if [[ "$selinux_state" != "unavailable" ]]; then
        echo "SELinux: ${selinux_state}"
    else
        echo "SELinux: tooling unavailable"
    fi
    if (( ${#sysctl_statuses[@]} > 0 )); then
        echo ""
        printf '%-35s %-12s %-12s\n' "Sysctl" "Value" "Expected"
        for row in "${sysctl_statuses[@]}"; do
            IFS='|' read -r key value expected <<<"$row"
            printf '%-35s %-12s %-12s\n' "$key" "$value" "$expected"
        done
    fi
    echo ""
    echo "## Critical service inventory"
    if $systemctl_ready; then
        if (( ${#unit_statuses[@]} > 0 )); then
            printf '%-38s %-12s %-12s\n' "Unit" "Enabled" "Active"
            for row in "${unit_statuses[@]}"; do
                IFS='|' read -r unit enabled active <<<"$row"
                printf '%-38s %-12s %-12s\n' "$unit" "$enabled" "$active"
            done
        else
            echo "No service data collected."
        fi
        echo ""
        echo "Timer units:"
        if (( ${#timer_statuses[@]} > 0 )); then
            printf '%-38s %-12s %-12s\n' "Timer" "Enabled" "Active"
            for row in "${timer_statuses[@]}"; do
                IFS='|' read -r timer enabled active <<<"$row"
                printf '%-38s %-12s %-12s\n' "$timer" "$enabled" "$active"
            done
        else
            echo "No timer data collected."
        fi
    else
        echo "systemctl unavailable or systemd inactive; skipping unit inspection."
        echo ""
        echo "Timer units:"
        echo "systemctl unavailable or systemd inactive; skipping timer inspection."
    fi
    echo ""
    echo "## Toolchain availability"
    for row in "${tool_statuses[@]}"; do
        IFS='|' read -r tool state <<<"$row"
        printf -- '- %-12s %s\n' "$tool" "$state"
    done
} >"$tmp"

mv "$tmp" "$OUTPUT"
trap - EXIT

cat "$OUTPUT"
echo "Environment report saved to $OUTPUT"
