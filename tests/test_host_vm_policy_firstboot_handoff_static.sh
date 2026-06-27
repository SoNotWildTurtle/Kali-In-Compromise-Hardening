#!/usr/bin/env bash
# MINC - Static tests for the host/VM firstboot handoff helper.
# Defensive validation only: verifies privacy-safe handoff behavior.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

python3 -m py_compile host_vm_policy_firstboot_handoff.py

cat > "$TMP_DIR/attestation.json" <<'JSON'
{"schema_version": 1, "created_utc": "2026-06-27T00:00:00Z", "snapshot_sha256": "abc123"}
JSON
cat > "$TMP_DIR/verify.json" <<'JSON'
{"schema_version": 1, "created_utc": "2026-06-27T00:00:01Z", "decision": "pass", "critical_findings": 0, "warning_findings": 0}
JSON

python3 host_vm_policy_firstboot_handoff.py \
  --attestation "$TMP_DIR/attestation.json" \
  --verify "$TMP_DIR/verify.json" \
  --restore-plan "$TMP_DIR/optional_restore_plan.json" \
  --approval-check "$TMP_DIR/optional_approval_check.json" \
  --ids-model-audit "$TMP_DIR/optional_model_audit.json" \
  --ids-audit-gate "$TMP_DIR/optional_audit_gate.json" \
  --ids-health-evidence "$TMP_DIR/optional_health_evidence.json" \
  --bundle "$TMP_DIR/policy_evidence_bundle.json" \
  --bundle-report "$TMP_DIR/policy_evidence_bundle.report" \
  --receipt "$TMP_DIR/policy_evidence_bundle_receipt.json" \
  --receipt-markdown "$TMP_DIR/policy_evidence_bundle_receipt.md" \
  --index "$TMP_DIR/firstboot_handoff.json" \
  --markdown "$TMP_DIR/firstboot_handoff.md" \
  --require-ready

python3 - "$TMP_DIR/firstboot_handoff.json" "$TMP_DIR/firstboot_handoff.md" <<'PY'
import json
import pathlib
import sys

index = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert index['component'] == 'host_vm_policy_firstboot_handoff'
assert index['decision'] == 'approved'
assert index['ok'] is True
assert index['release_gate'] == 'pass'
assert index['bundle_sha256']
assert index['receipt_sha256']
assert 'packets' in index['privacy_note']
assert 'Host VM Firstboot Policy Handoff' in markdown
PY

cat > "$TMP_DIR/verify.json" <<'JSON'
{"schema_version": 1, "created_utc": "2026-06-27T00:00:01Z", "decision": "restore_review", "critical_findings": 1, "warning_findings": 0}
JSON

if python3 host_vm_policy_firstboot_handoff.py \
  --attestation "$TMP_DIR/attestation.json" \
  --verify "$TMP_DIR/verify.json" \
  --restore-plan "$TMP_DIR/optional_restore_plan.json" \
  --approval-check "$TMP_DIR/optional_approval_check.json" \
  --ids-model-audit "$TMP_DIR/optional_model_audit.json" \
  --ids-audit-gate "$TMP_DIR/optional_audit_gate.json" \
  --ids-health-evidence "$TMP_DIR/optional_health_evidence.json" \
  --bundle "$TMP_DIR/policy_evidence_bundle.json" \
  --bundle-report "$TMP_DIR/policy_evidence_bundle.report" \
  --receipt "$TMP_DIR/policy_evidence_bundle_receipt.json" \
  --receipt-markdown "$TMP_DIR/policy_evidence_bundle_receipt.md" \
  --index "$TMP_DIR/firstboot_handoff.json" \
  --markdown "$TMP_DIR/firstboot_handoff.md" \
  --require-ready; then
  echo 'expected --require-ready to fail when evidence needs review' >&2
  exit 1
fi

python3 - "$TMP_DIR/firstboot_handoff.json" <<'PY'
import json
import pathlib
import sys

index = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert index['decision'] == 'deferred'
assert index['ok'] is False
assert index['release_gate'] == 'stop'
assert 'policy_verify' in index['review_items']
PY

echo '[static-check] host_vm_policy_firstboot_handoff.py passed static behavior checks'
