#!/usr/bin/env bash
# MINC - Static and behavioral checks for passive firstboot handoff release receipts.
# Defensive validation only: uses synthetic aggregate gate evidence.

set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

MODULE="host_vm_policy_firstboot_release_receipt.py"
PASS_GATE="$TMP_DIR/firstboot_handoff_gate.pass.json"
BLOCK_GATE="$TMP_DIR/firstboot_handoff_gate.block.json"
MALFORMED_GATE="$TMP_DIR/firstboot_handoff_gate.malformed.json"
RECEIPT_JSON="$TMP_DIR/firstboot_release_receipt.json"
RECEIPT_REPORT="$TMP_DIR/firstboot_release_receipt.report"

[[ -f "$MODULE" ]]
python3 -m py_compile "$MODULE"

grep -q 'aggregate evidence only' "$MODULE"
grep -q 'release_receipt_ready' "$MODULE"
grep -q 'release_receipt_blocked' "$MODULE"
grep -q 'changes_live_state' "$MODULE"
grep -q 'reads_raw_telemetry' "$MODULE"

cat > "$PASS_GATE" <<'JSON'
{
  "schema_version": 1,
  "gate": "host_vm_policy_firstboot_handoff_gate.py",
  "gate_version": "1.0.0",
  "created_utc": "2026-06-30T00:00:00Z",
  "handoff_path": "/tmp/host_vm_policy_firstboot_handoff.json",
  "decision": "release_ready",
  "changes_live_state": false,
  "reads_raw_telemetry": false,
  "checks_passed": 3,
  "checks_failed": 0,
  "checks": [
    {"name": "schema_version", "status": "pass", "detail": "schema version ok"},
    {"name": "safety_no_mutation", "status": "pass", "detail": "no mutation"},
    {"name": "privacy_boundary", "status": "pass", "detail": "aggregate only"}
  ]
}
JSON

python3 "$MODULE" "$PASS_GATE" --strict --output "$RECEIPT_JSON" --report "$RECEIPT_REPORT"
grep -q '"decision": "release_receipt_ready"' "$RECEIPT_JSON"
grep -q '"release_ready": true' "$RECEIPT_JSON"
grep -q '^decision=release_receipt_ready$' "$RECEIPT_REPORT"
grep -q '^release_ready=true$' "$RECEIPT_REPORT"

cat > "$BLOCK_GATE" <<'JSON'
{
  "schema_version": 1,
  "gate": "host_vm_policy_firstboot_handoff_gate.py",
  "gate_version": "1.0.0",
  "created_utc": "2026-06-30T00:00:00Z",
  "handoff_path": "/tmp/host_vm_policy_firstboot_handoff.json",
  "decision": "release_blocked",
  "changes_live_state": false,
  "reads_raw_telemetry": false,
  "checks_passed": 2,
  "checks_failed": 1,
  "checks": [
    {"name": "schema_version", "status": "pass", "detail": "schema version ok"},
    {"name": "safety_no_mutation", "status": "pass", "detail": "no mutation"},
    {"name": "validation_valid", "status": "fail", "detail": "profile validation failed"}
  ]
}
JSON

if python3 "$MODULE" "$BLOCK_GATE" --strict --output "$RECEIPT_JSON" --report "$RECEIPT_REPORT"; then
    echo "strict receipt generation should fail for blocked gate evidence" >&2
    exit 1
fi
grep -q '"decision": "release_receipt_blocked"' "$RECEIPT_JSON"
grep -q 'gate decision must be release_ready' "$RECEIPT_JSON"
grep -q 'gate check not passing: validation_valid' "$RECEIPT_REPORT"

cat > "$MALFORMED_GATE" <<'JSON'
{
  "schema_version": 1,
  "gate": "unexpected_gate.py",
  "decision": "release_ready",
  "changes_live_state": true,
  "reads_raw_telemetry": true,
  "checks_passed": 0,
  "checks_failed": 0,
  "checks": "not-a-list"
}
JSON

python3 "$MODULE" "$MALFORMED_GATE" --output "$RECEIPT_JSON" --report "$RECEIPT_REPORT"
grep -q '"decision": "release_receipt_blocked"' "$RECEIPT_JSON"
grep -q 'gate evidence missing required field: created_utc' "$RECEIPT_JSON"
grep -q 'gate must be host_vm_policy_firstboot_handoff_gate.py' "$RECEIPT_JSON"
grep -q 'gate evidence must declare changes_live_state=false' "$RECEIPT_JSON"
grep -q 'gate evidence must declare reads_raw_telemetry=false' "$RECEIPT_JSON"
grep -q 'gate check not passing: checks_not_list' "$RECEIPT_REPORT"
grep -q '^decision=release_receipt_blocked$' "$RECEIPT_REPORT"

echo "firstboot release receipt static checks passed"
