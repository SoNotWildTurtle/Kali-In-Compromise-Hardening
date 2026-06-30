#!/usr/bin/env bash
# MINC - Static and behavioral checks for passive firstboot release-readiness summaries.
# Defensive validation only: uses synthetic aggregate receipt evidence.

set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

MODULE="host_vm_policy_firstboot_release_summary.py"
READY_RECEIPT="$TMP_DIR/firstboot_release_receipt.ready.json"
BLOCKED_RECEIPT="$TMP_DIR/firstboot_release_receipt.blocked.json"
BAD_RECEIPT="$TMP_DIR/firstboot_release_receipt.bad.json"
SUMMARY_JSON="$TMP_DIR/firstboot_release_summary.json"
SUMMARY_REPORT="$TMP_DIR/firstboot_release_summary.report"

[[ -f "$MODULE" ]]
python3 -m py_compile "$MODULE"

grep -q 'aggregate receipt evidence only' "$MODULE"
grep -q 'summary_ready' "$MODULE"
grep -q 'summary_blocked' "$MODULE"
grep -q 'release_receipt_ready' "$MODULE"
grep -q 'release_receipt_blocked' "$MODULE"
grep -q 'changes_live_state' "$MODULE"
grep -q 'reads_raw_telemetry' "$MODULE"

cat > "$READY_RECEIPT" <<'JSON'
{
  "schema_version": 1,
  "receipt": "host_vm_policy_firstboot_release_receipt.py",
  "receipt_version": "1.0.0",
  "created_utc": "2026-06-30T00:00:00Z",
  "source_gate_path": "/tmp/firstboot_handoff_gate.json",
  "source_gate": "host_vm_policy_firstboot_handoff_gate.py",
  "source_gate_version": "1.0.0",
  "source_gate_decision": "release_ready",
  "release_ready": true,
  "decision": "release_receipt_ready",
  "changes_live_state": false,
  "reads_raw_telemetry": false,
  "checks_passed": 3,
  "checks_failed": 0,
  "blocking_issues": [],
  "handoff_scope": {
    "aggregate_evidence_only": true,
    "mutates_host_or_vm_state": false
  },
  "rollback": {
    "live_state_rollback_required": false,
    "action": "revert receipt artifact generation and workflow receipt step only"
  },
  "follow_up": []
}
JSON

cat > "$BLOCKED_RECEIPT" <<'JSON'
{
  "schema_version": 1,
  "receipt": "host_vm_policy_firstboot_release_receipt.py",
  "receipt_version": "1.0.0",
  "created_utc": "2026-06-30T00:00:00Z",
  "source_gate_path": "/tmp/firstboot_handoff_gate.blocked.json",
  "source_gate": "host_vm_policy_firstboot_handoff_gate.py",
  "source_gate_version": "1.0.0",
  "source_gate_decision": "release_blocked",
  "release_ready": false,
  "decision": "release_receipt_blocked",
  "changes_live_state": false,
  "reads_raw_telemetry": false,
  "checks_passed": 2,
  "checks_failed": 1,
  "blocking_issues": ["gate decision must be release_ready"],
  "handoff_scope": {
    "aggregate_evidence_only": true,
    "mutates_host_or_vm_state": false
  },
  "rollback": {
    "live_state_rollback_required": false,
    "action": "revert receipt artifact generation and workflow receipt step only"
  },
  "follow_up": []
}
JSON

python3 "$MODULE" "$READY_RECEIPT" \
  --expected-blocked-receipt "$BLOCKED_RECEIPT" \
  --strict \
  --output "$SUMMARY_JSON" \
  --report "$SUMMARY_REPORT"
grep -q '"decision": "summary_ready"' "$SUMMARY_JSON"
grep -q '"aggregate_evidence_only": true' "$SUMMARY_JSON"
grep -q '"requires_human_review_before_live_firstboot_wiring": true' "$SUMMARY_JSON"
grep -q '^decision=summary_ready$' "$SUMMARY_REPORT"
grep -q '^expected_blocked_decision=release_receipt_blocked$' "$SUMMARY_REPORT"
grep -q '^blocking_issue_count=0$' "$SUMMARY_REPORT"

python3 "$MODULE" "$READY_RECEIPT" --strict --output "$SUMMARY_JSON" --report "$SUMMARY_REPORT"
grep -q '"decision": "summary_ready"' "$SUMMARY_JSON"
grep -q '"present": false' "$SUMMARY_JSON"
grep -q '^expected_blocked_present=false$' "$SUMMARY_REPORT"

cat > "$BAD_RECEIPT" <<'JSON'
{
  "schema_version": 1,
  "receipt": "host_vm_policy_firstboot_release_receipt.py",
  "receipt_version": "1.0.0",
  "created_utc": "2026-06-30T00:00:00Z",
  "release_ready": false,
  "decision": "release_receipt_blocked",
  "changes_live_state": true,
  "reads_raw_telemetry": true,
  "blocking_issues": [],
  "handoff_scope": {
    "aggregate_evidence_only": false
  },
  "rollback": {
    "live_state_rollback_required": true
  }
}
JSON

if python3 "$MODULE" "$BAD_RECEIPT" --strict --output "$SUMMARY_JSON" --report "$SUMMARY_REPORT"; then
    echo "strict summary generation should fail for malformed ready receipt evidence" >&2
    exit 1
fi
grep -q '"decision": "summary_blocked"' "$SUMMARY_JSON"
grep -q 'ready receipt decision must be release_receipt_ready' "$SUMMARY_JSON"
grep -q 'ready receipt must declare changes_live_state=false' "$SUMMARY_JSON"
grep -q 'ready receipt must declare reads_raw_telemetry=false' "$SUMMARY_JSON"
grep -q 'ready receipt rollback must not require live-state changes' "$SUMMARY_JSON"
grep -q '^decision=summary_blocked$' "$SUMMARY_REPORT"
grep -q '^summary_ready=false$' "$SUMMARY_REPORT"

echo "firstboot release summary static checks passed"
