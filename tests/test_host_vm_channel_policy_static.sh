#!/usr/bin/env bash
# Static validation for host_vm_channel_policy.py.
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

GOOD_POLICY="${TMP_DIR}/good.json"
BAD_POLICY="${TMP_DIR}/bad.json"

cat >"${GOOD_POLICY}" <<'JSON'
{
  "protocol": "ssh",
  "direction": "vm-to-host",
  "hypervisor": "virtualbox",
  "management_target": "192.168.56.1",
  "allowed_ports": [22],
  "require_host_key_pinning": true,
  "allow_password_authentication": false,
  "require_transcript_logging": true,
  "require_time_sync": true,
  "allow_clipboard_sharing": false,
  "allow_shared_folders": false,
  "max_session_minutes": 30,
  "break_glass": {
    "documented_procedure": "Use console-only maintenance with transcript capture."
  }
}
JSON

cat >"${BAD_POLICY}" <<'JSON'
{
  "protocol": "telnet",
  "direction": "sideways",
  "hypervisor": "mystery",
  "management_target": "8.8.8.8",
  "allowed_ports": [23, 3389, 5985],
  "require_host_key_pinning": false,
  "allow_password_authentication": true,
  "require_transcript_logging": false,
  "require_time_sync": false,
  "allow_clipboard_sharing": true,
  "allow_shared_folders": true,
  "max_session_minutes": 999,
  "break_glass": {}
}
JSON

python3 host_vm_channel_policy.py --policy "${GOOD_POLICY}" >/tmp/host_vm_channel_policy_good.out
if ! grep -q "PASS" /tmp/host_vm_channel_policy_good.out; then
  echo "Expected good policy to pass" >&2
  cat /tmp/host_vm_channel_policy_good.out >&2
  exit 1
fi

if python3 host_vm_channel_policy.py --policy "${BAD_POLICY}" >/tmp/host_vm_channel_policy_bad.out 2>&1; then
  echo "Expected bad policy to fail" >&2
  cat /tmp/host_vm_channel_policy_bad.out >&2
  exit 1
fi

grep -q "PROTOCOL.UNSUPPORTED\|protocol.unsupported" /tmp/host_vm_channel_policy_bad.out
grep -q "target.not_private" /tmp/host_vm_channel_policy_bad.out
grep -q "auth.password_enabled" /tmp/host_vm_channel_policy_bad.out
grep -q "hypervisor.shared_folders" /tmp/host_vm_channel_policy_bad.out

python3 host_vm_channel_policy.py --policy "${BAD_POLICY}" --json >/tmp/host_vm_channel_policy_bad.json || true
grep -q '"ok": false' /tmp/host_vm_channel_policy_bad.json

echo "host VM channel policy static tests passed"
