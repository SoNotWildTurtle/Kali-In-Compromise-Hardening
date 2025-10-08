#!/bin/bash
# host_hardening_windows.sh - automate hardening of a Windows 11 host
set -euo pipefail

# Variables - adjust to your environment
HOST_IP="${HOST_IP:-192.168.1.100}"
SSH_USER="${SSH_USER:-admin}"
SSH_KEY="${SSH_KEY:-/home/kaliuser/.ssh/id_rsa_kali_windows}"
PS_SCRIPT_LOCAL="${PS_SCRIPT_LOCAL:-windows_hardening.ps1}"
PS_SCRIPT_REMOTE="${PS_SCRIPT_REMOTE:-C:\\Users\\${SSH_USER}\\windows_hardening.ps1}"

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
