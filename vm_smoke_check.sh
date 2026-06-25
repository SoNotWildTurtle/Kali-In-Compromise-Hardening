#!/usr/bin/env bash
# MINC - Read-only post-boot smoke validation for the hardened Kali VM.
# Defensive validation only: this script does not alter firewall, host, IDS, or systemd state.

set -u -o pipefail

STRICT=false
LOG_FILE="${VM_SMOKE_LOG:-/var/log/vm_smoke_check.log}"
REPORT_FILE="${VM_SMOKE_REPORT:-/var/log/vm_smoke_check.report}"

usage() {
    cat <<'USAGE'
Usage: vm_smoke_check.sh [--strict] [--log PATH] [--report PATH]

Runs read-only post-boot checks for the hardened Kali VM:
  - firstboot completion signal
  - core hardening scripts and systemd units
  - key timers for IDS, audit, restore, and monitoring
  - host/VM communication guard status
  - logging paths and audit artifacts
  - NN IDS audit/gate outputs when present

Options:
  --strict       Treat warnings as failures. Useful for release validation.
  --log PATH    Write detailed log output to PATH. Default: /var/log/vm_smoke_check.log
  --report PATH Write compact PASS/WARN/FAIL report to PATH. Default: /var/log/vm_smoke_check.report
  -h, --help    Show this help text.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict)
            STRICT=true
            shift
            ;;
        --log)
            LOG_FILE="${2:?--log requires a path}"
            shift 2
            ;;
        --report)
            REPORT_FILE="${2:?--report requires a path}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$REPORT_FILE")" 2>/dev/null || true
: >"$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/vm_smoke_check.log"
: >"$REPORT_FILE" 2>/dev/null || REPORT_FILE="/tmp/vm_smoke_check.report"

log() {
    printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG_FILE" >/dev/null
}

record() {
    local status="$1"
    shift
    local message="$*"
    printf '%s %s\n' "$status" "$message" | tee -a "$REPORT_FILE" >/dev/null
    log "$status $message"
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    esac
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

unit_exists() {
    local unit="$1"
    systemctl list-unit-files "$unit" >/dev/null 2>&1
}

unit_active_or_enabled() {
    local unit="$1"
    if ! unit_exists "$unit"; then
        record FAIL "systemd unit missing: $unit"
        return
    fi
    local active="unknown"
    local enabled="unknown"
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    if [[ "$active" == "active" || "$enabled" == "enabled" || "$enabled" == "static" ]]; then
        record PASS "systemd unit present and active/enabled: $unit active=$active enabled=$enabled"
    else
        record WARN "systemd unit present but not active/enabled: $unit active=$active enabled=$enabled"
    fi
}

file_present() {
    local path="$1"
    if [[ -e "$path" ]]; then
        record PASS "file present: $path"
    else
        record WARN "file missing: $path"
    fi
}

file_nonempty() {
    local path="$1"
    if [[ -s "$path" ]]; then
        record PASS "file present and non-empty: $path"
    elif [[ -e "$path" ]]; then
        record WARN "file present but empty: $path"
    else
        record WARN "file missing: $path"
    fi
}

check_json_file() {
    local path="$1"
    if [[ ! -s "$path" ]]; then
        record WARN "JSON artifact missing or empty: $path"
        return
    fi
    if have_cmd python3 && python3 -m json.tool "$path" >/dev/null 2>&1; then
        record PASS "valid JSON artifact: $path"
    else
        record WARN "JSON artifact could not be parsed: $path"
    fi
}

log "starting hardened Kali VM smoke validation"

if [[ $EUID -ne 0 ]]; then
    record WARN "not running as root; some systemd/log/firewall checks may be incomplete"
else
    record PASS "running with root privileges for full read-only validation"
fi

for path in \
    /usr/local/bin/firstboot.sh \
    /usr/local/bin/host_vm_comm_guard.sh \
    /usr/local/bin/nn_ids_model_audit.py \
    /usr/local/bin/nn_ids_audit_gate.py \
    /usr/local/bin/network_io_monitor.sh \
    /usr/local/bin/internet_access_monitor.sh; do
    file_present "$path"
done

for unit in \
    host_vm_comm_guard.service \
    network_io_monitor.service \
    internet_access_monitor.timer \
    nn_ids_capture.timer \
    nn_ids_retrain.timer \
    nn_ids_healthcheck.timer \
    nn_ids_snapshot.timer \
    nn_ids_restore.timer \
    nn_ids_model_audit.timer \
    nn_ids_audit_gate.timer \
    port_socket_monitor.timer \
    nn_ids_autoblock.timer \
    nn_ids_report.timer \
    threat_feed_blocklist.timer \
    nn_ids_resource_monitor.timer \
    nn_ids_sanitize.timer; do
    unit_active_or_enabled "$unit"
done

if systemctl is-enabled firstboot.service >/dev/null 2>&1; then
    record WARN "firstboot.service is still enabled; firstboot may not have completed cleanly"
else
    record PASS "firstboot.service is not enabled after first boot"
fi

file_nonempty /var/log/debsums.log
file_nonempty /var/log/lynis.log
file_nonempty /var/log/nn_ids_model_audit.firstboot.log
file_nonempty /var/log/nn_ids_audit_gate.firstboot.log
file_present /etc/nn_ids.conf

check_json_file /var/lib/nn_ids/model_audit.json
check_json_file /var/lib/nn_ids/audit_gate.json

if [[ -x /usr/local/bin/host_vm_comm_guard.sh ]]; then
    if /usr/local/bin/host_vm_comm_guard.sh status >>"$LOG_FILE" 2>&1; then
        record PASS "host/VM communication guard status command succeeded"
    else
        record WARN "host/VM communication guard status command returned non-zero; inspect $LOG_FILE"
    fi
fi

if have_cmd nft; then
    if nft list ruleset 2>/dev/null | grep -q 'host_vm_comm_guard'; then
        record PASS "nftables ruleset contains host_vm_comm_guard markers"
    else
        record WARN "nftables ruleset does not show host_vm_comm_guard markers"
    fi
else
    record WARN "nft command unavailable; firewall guard ruleset could not be inspected"
fi

if have_cmd ss; then
    if ss -lntup >>"$LOG_FILE" 2>&1; then
        record PASS "listening sockets captured for review"
    else
        record WARN "could not capture listening sockets"
    fi
else
    record WARN "ss command unavailable; socket inventory skipped"
fi

if have_cmd journalctl; then
    journalctl --no-pager -u firstboot.service -n 80 >>"$LOG_FILE" 2>&1 || true
    journalctl --no-pager -u host_vm_comm_guard.service -n 80 >>"$LOG_FILE" 2>&1 || true
    record PASS "recent firstboot and communication guard journal entries copied to log"
else
    record WARN "journalctl unavailable; systemd journal extraction skipped"
fi

if [[ "$STRICT" == true && "$WARN_COUNT" -gt 0 ]]; then
    FAIL_COUNT=$((FAIL_COUNT + WARN_COUNT))
    record FAIL "strict mode promoted warnings to failures"
fi

summary="summary: pass=$PASS_COUNT warn=$WARN_COUNT fail=$FAIL_COUNT log=$LOG_FILE report=$REPORT_FILE"
log "$summary"
printf '%s\n' "$summary" | tee -a "$REPORT_FILE"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
