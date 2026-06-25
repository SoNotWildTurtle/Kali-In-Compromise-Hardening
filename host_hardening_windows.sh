#!/bin/bash
# host_hardening_windows.sh - automate hardening of a Windows 11 host
set -euo pipefail

# Variables - adjust to your environment
HOST_IP="${HOST_IP:-192.168.1.100}"
SSH_USER="${SSH_USER:-admin}"
SSH_KEY="${SSH_KEY:-/home/kaliuser/.ssh/id_rsa_kali_windows}"
PS_SCRIPT_LOCAL="${PS_SCRIPT_LOCAL:-windows_hardening.ps1}"
PS_SCRIPT_REMOTE="${PS_SCRIPT_REMOTE:-C:\\Users\\${SSH_USER}\\windows_hardening.ps1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANNEL_POLICY_VALIDATOR="${CHANNEL_POLICY_VALIDATOR:-$SCRIPT_DIR/host_vm_channel_policy.py}"
CHANNEL_POLICY_FILE="${CHANNEL_POLICY_FILE:-$SCRIPT_DIR/host_vm_channel_policy.example.json}"
CHANNEL_POLICY_CHECK_LOCAL_FILES="${CHANNEL_POLICY_CHECK_LOCAL_FILES:-1}"
CHANNEL_POLICY_REPORT="${CHANNEL_POLICY_REPORT:-}"

run_channel_policy_preflight() {
    if [ "${KALI_HARDENING_SKIP_CHANNEL_POLICY:-0}" = "1" ]; then
        cat >&2 <<'WARN'
WARNING: KALI_HARDENING_SKIP_CHANNEL_POLICY=1 is set.
The host/VM management-channel policy preflight is being bypassed for a documented break-glass session.
Capture transcript logs, keep the maintenance window short, and rerun policy validation before normal automation resumes.
WARN
        return 0
    fi

    if [ ! -r "$CHANNEL_POLICY_VALIDATOR" ]; then
        echo "Channel policy validator is missing or unreadable: $CHANNEL_POLICY_VALIDATOR" >&2
        exit 1
    fi

    if [ ! -f "$CHANNEL_POLICY_FILE" ]; then
        echo "Channel policy file not found: $CHANNEL_POLICY_FILE" >&2
        exit 1
    fi

    local validator_args=(--policy "$CHANNEL_POLICY_FILE")
    if [ "$CHANNEL_POLICY_CHECK_LOCAL_FILES" = "1" ]; then
        validator_args+=(--check-local-files)
    fi

    echo "Validating host/VM hardening channel policy before Windows host automation..."
    if [ -n "$CHANNEL_POLICY_REPORT" ]; then
        mkdir -p "$(dirname "$CHANNEL_POLICY_REPORT")"
        if python3 "$CHANNEL_POLICY_VALIDATOR" "${validator_args[@]}" --json >"$CHANNEL_POLICY_REPORT"; then
            cat "$CHANNEL_POLICY_REPORT"
        else
            cat "$CHANNEL_POLICY_REPORT" >&2
            exit 1
        fi
    else
        python3 "$CHANNEL_POLICY_VALIDATOR" "${validator_args[@]}"
    fi
}

run_channel_policy_preflight

# Verify prerequisites
if [ ! -f "$SSH_KEY" ]; then
    echo "SSH key not found at $SSH_KEY" >&2
    exit 1
fi

if [ ! -f "$PS_SCRIPT_LOCAL" ]; then
    echo "PowerShell script not found at $PS_SCRIPT_LOCAL" >&2
    exit 1
fi

# Wait for SSH connectivity
MAX_WAIT=300
WAIT_INTERVAL=10
TIME_PASSED=0
printf 'Waiting for SSH on %s...\n' "$HOST_IP"
until ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=5 "$SSH_USER@$HOST_IP" exit >/dev/null 2>&1; do
    sleep "$WAIT_INTERVAL"
    TIME_PASSED=$((TIME_PASSED + WAIT_INTERVAL))
    if [ "$TIME_PASSED" -ge "$MAX_WAIT" ]; then
        echo "Timeout waiting for SSH on $HOST_IP" >&2
        exit 1
    fi
done

# Transfer the PowerShell script
scp -i "$SSH_KEY" "$PS_SCRIPT_LOCAL" "$SSH_USER@$HOST_IP:$PS_SCRIPT_REMOTE"

# Execute the PowerShell script on the host
ssh -i "$SSH_KEY" "$SSH_USER@$HOST_IP" "powershell -ExecutionPolicy Bypass -File '$PS_SCRIPT_REMOTE'"

# Remove the script from the host
ssh -i "$SSH_KEY" "$SSH_USER@$HOST_IP" "Remove-Item '$PS_SCRIPT_REMOTE' -Force"

echo "Host hardening process completed."
