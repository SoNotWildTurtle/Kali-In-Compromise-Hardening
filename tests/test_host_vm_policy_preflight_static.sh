#!/usr/bin/env bash
# Static validation for channel-policy preflight wiring.
set -euo pipefail

for script in host_hardening_windows.sh host_hardening_linux.sh; do
  grep -q 'run_channel_policy_preflight' "$script"
  grep -q 'host_vm_channel_policy.py' "$script"
  grep -q 'KALI_HARDENING_SKIP_CHANNEL_POLICY' "$script"
  grep -q -- '--check-local-files' "$script"
  grep -q 'Channel policy validator is missing or not executable' "$script"
  grep -q 'Channel policy file not found' "$script"
done

echo "channel policy preflight static tests passed"
