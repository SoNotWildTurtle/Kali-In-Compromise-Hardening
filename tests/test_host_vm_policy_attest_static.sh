#!/usr/bin/env bash
# MINC - Static validation for host_vm_policy_attest.py.
# Defensive test only: validates local attestation behavior without changing firewall or host state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    printf '[policy-attest-static][FAIL] %s\n' "$*" >&2
    exit 1
}

printf '[policy-attest-static] checking Python syntax\n'
python3 -m py_compile host_vm_policy_attest.py

printf '[policy-attest-static] checking service sandboxing\n'
grep -q '^NoNewPrivileges=true' host_vm_policy_attest.service || fail 'service missing NoNewPrivileges=true'
grep -q '^PrivateTmp=true' host_vm_policy_attest.service || fail 'service missing PrivateTmp=true'
grep -q '^ProtectSystem=strict' host_vm_policy_attest.service || fail 'service missing ProtectSystem=strict'
grep -q '^ReadWritePaths=/var/lib/host_vm_comm_guard /var/log /etc/host_vm_comm_guard' host_vm_policy_attest.service || fail 'service write paths are too broad or missing'
grep -q '^CapabilityBoundingSet=$' host_vm_policy_attest.service || fail 'service should not retain Linux capabilities'

printf '[policy-attest-static] checking timer safety\n'
grep -q '^OnUnitActiveSec=1h' host_vm_policy_attest.timer || fail 'timer should refresh hourly'
grep -q '^RandomizedDelaySec=' host_vm_policy_attest.timer || fail 'timer should use randomized delay'
grep -q '^Persistent=true' host_vm_policy_attest.timer || fail 'timer should be persistent'

printf '[policy-attest-static] running non-privileged no-sign snapshot test\n'
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
python3 host_vm_policy_attest.py \
    --output "$TMP_DIR/policy_attestation.json" \
    --signature "$TMP_DIR/policy_attestation.sig" \
    --report "$TMP_DIR/policy_attestation.report" \
    --ids-audit "$TMP_DIR/missing_model_audit.json" \
    --ids-gate "$TMP_DIR/missing_audit_gate.json" \
    --no-sign >/tmp/host_vm_policy_attest_test.out

python3 - "$TMP_DIR/policy_attestation.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding='utf-8'))
required = ['schema_version', 'created_utc', 'guard_files', 'nftables', 'systemd', 'ids_model_audit', 'ids_audit_gate', 'snapshot_sha256', 'signature']
missing = [key for key in required if key not in data]
if missing:
    raise SystemExit(f'missing keys: {missing}')
if data['schema_version'] != 1:
    raise SystemExit('unexpected schema version')
if not data['snapshot_sha256'] or len(data['snapshot_sha256']) != 64:
    raise SystemExit('snapshot_sha256 is not a sha256 hex digest')
if data['signature'].get('signed') is not False:
    raise SystemExit('no-sign mode should report signed=false')
if not isinstance(data['guard_files'], list) or len(data['guard_files']) < 2:
    raise SystemExit('expected guard file digest entries')
PY

grep -q '^snapshot_sha256=' "$TMP_DIR/policy_attestation.report" || fail 'compact report missing snapshot hash'

printf '[policy-attest-static] checking ISO and firstboot references\n'
grep -q 'host_vm_policy_attest.py' build_custom_iso.sh || fail 'build_custom_iso.sh must package attestation script'
grep -q 'host_vm_policy_attest.service' build_custom_iso.sh || fail 'build_custom_iso.sh must package attestation service'
grep -q 'host_vm_policy_attest.timer' build_custom_iso.sh || fail 'build_custom_iso.sh must package attestation timer'
grep -q 'host_vm_policy_attest.timer' firstboot.sh || fail 'firstboot.sh must enable attestation timer'
grep -q 'host_vm_policy_attest.py' firstboot.sh || fail 'firstboot.sh must run initial attestation'

printf '[policy-attest-static] all checks passed\n'
