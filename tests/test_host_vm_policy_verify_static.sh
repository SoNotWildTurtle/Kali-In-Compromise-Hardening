#!/usr/bin/env bash
# MINC - Static and behavior checks for the defensive host/VM policy verifier.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

python3 -m py_compile host_vm_policy_verify.py

cat >"$TMP_DIR/base.json" <<'JSON'
{
  "guard_files": [
    {"path": "/etc/host_vm_comm_guard.conf", "exists": true, "mode": "0o640", "sha256": "aaa"},
    {"path": "/etc/nftables.d/host_vm_comm_guard.nft", "exists": true, "mode": "0o640", "sha256": "bbb"}
  ],
  "nftables": {"table_present": true, "contains_guard_prefixes": true, "stdout_sha256": "rules"},
  "systemd": {
    "host_vm_comm_guard.service": {"active": "active", "enabled": "enabled"},
    "host_vm_policy_attest.timer": {"active": "active", "enabled": "enabled"},
    "nn_ids_model_audit.timer": {"active": "active", "enabled": "enabled"},
    "nn_ids_audit_gate.timer": {"active": "active", "enabled": "enabled"},
    "nn_ids_restore.timer": {"active": "active", "enabled": "enabled"}
  },
  "ids_audit_gate": {"decision": "accept"},
  "ids_model_audit": {"balanced_accuracy": 0.98, "macro_f1": 0.97, "robustness_index": 0.92, "drift_detected": false}
}
JSON
cp "$TMP_DIR/base.json" "$TMP_DIR/current.json"

python3 host_vm_policy_verify.py \
  --baseline "$TMP_DIR/base.json" \
  --current "$TMP_DIR/current.json" \
  --output "$TMP_DIR/out_accept.json" \
  --report "$TMP_DIR/report_accept.txt" >/dev/null
python3 - <<'PY' "$TMP_DIR/out_accept.json"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert result['decision'] == 'accept', result
assert result['critical_findings'] == 0, result
assert result['warning_findings'] == 0, result
PY

python3 - <<'PY' "$TMP_DIR/current.json"
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
data['guard_files'][0]['sha256'] = 'tampered'
path.write_text(json.dumps(data))
PY
if python3 host_vm_policy_verify.py \
  --baseline "$TMP_DIR/base.json" \
  --current "$TMP_DIR/current.json" \
  --output "$TMP_DIR/out_restore.json" \
  --report "$TMP_DIR/report_restore.txt" >/dev/null; then
    echo "expected critical drift to return non-zero" >&2
    exit 1
fi
python3 - <<'PY' "$TMP_DIR/out_restore.json"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert result['decision'] == 'restore_review', result
assert result['critical_findings'] >= 1, result
PY

cp "$TMP_DIR/base.json" "$TMP_DIR/init_current.json"
python3 host_vm_policy_verify.py \
  --current "$TMP_DIR/init_current.json" \
  --baseline "$TMP_DIR/new_baseline.json" \
  --init-baseline \
  --output "$TMP_DIR/out_init.json" \
  --report "$TMP_DIR/report_init.txt" >/dev/null
test -s "$TMP_DIR/new_baseline.json"

grep -q 'NoNewPrivileges=true' host_vm_policy_verify.service
grep -q 'ProtectSystem=strict' host_vm_policy_verify.service
grep -q 'RestrictAddressFamilies=AF_UNIX' host_vm_policy_verify.service
grep -q 'OnUnitActiveSec=6h' host_vm_policy_verify.timer
grep -q 'host_vm_policy_verify.py' build_custom_iso.sh
grep -q 'host_vm_policy_verify.timer' firstboot.sh
grep -q 'host_vm_policy_verify.py --init-baseline' firstboot.sh
grep -q 'host_vm_policy_verify.py' docs/host_vm_policy_verify.md

echo "host_vm_policy_verify static tests passed"
