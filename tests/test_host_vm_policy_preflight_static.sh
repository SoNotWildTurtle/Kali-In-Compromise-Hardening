#!/usr/bin/env bash
# Static validation for channel-policy preflight wiring.
set -euo pipefail

for script in host_hardening_windows.sh host_hardening_linux.sh; do
  grep -q 'run_channel_policy_preflight' "$script"
  grep -q 'host_vm_channel_policy.py' "$script"
  grep -q 'KALI_HARDENING_SKIP_CHANNEL_POLICY' "$script"
  grep -q -- '--check-local-files' "$script"
  grep -q -- '--json >"$CHANNEL_POLICY_REPORT"' "$script"
  grep -q 'CHANNEL_POLICY_REPORT' "$script"
  grep -q 'Channel policy validator is missing or unreadable' "$script"
  grep -q 'Channel policy file not found' "$script"
done

# Linux and Windows entrypoints intentionally invoke the Python validator directly,
# so a readable checkout is sufficient and executable mode is not required.
if grep -q '\[ ! -x "$CHANNEL_POLICY_VALIDATOR" \]' host_hardening_linux.sh host_hardening_windows.sh; then
  echo "channel policy validator checks must be readable-only, not executable-only" >&2
  exit 1
fi

echo "channel policy preflight static tests passed"
