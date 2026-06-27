#!/usr/bin/env bash
# MINC - Static tests for the host/VM policy evidence bundle utility.
# Defensive validation only: verifies read-only summaries, safe defaults, and privacy boundaries.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

write_json() {
    local path="$1"
    local payload="$2"
    printf '%s\n' "$payload" > "$path"
}

ATTEST="$TMP_DIR/policy_attestation.json"
VERIFY="$TMP_DIR/policy_verify.json"
PLAN="$TMP_DIR/policy_restore_plan.json"
APPROVAL="$TMP_DIR/policy_restore_approval_check.json"
IDS_HEALTH="$TMP_DIR/health_evidence.json"
OUTPUT="$TMP_DIR/bundle.json"
REPORT="$TMP_DIR/bundle.report"

write_json "$ATTEST" '{"schema_version":1,"created_utc":"2026-06-26T00:00:00Z","snapshot_sha256":"abc123","private_key":"must-not-leak"}'
write_json "$VERIFY" '{"schema_version":1,"created_utc":"2026-06-26T00:00:01Z","decision":"accept","critical_findings":0,"warning_findings":0,"secret_token":"must-not-leak"}'
write_json "$PLAN" '{"schema_version":1,"created_utc":"2026-06-26T00:00:02Z","decision":"no_restore_needed","changes_live_state":false}'
write_json "$APPROVAL" '{"schema_version":1,"created_utc":"2026-06-26T00:00:03Z","decision":"approval_valid","changes_live_state":false,"signature":"must-not-leak"}'
write_json "$IDS_HEALTH" '{"component":"nn_ids","generated_at":"2026-06-26T00:00:04Z","status":"pass","ok":true,"failing_controls":[],"warning_controls":[]}'

python3 host_vm_policy_evidence_bundle.py \
    --attestation "$ATTEST" \
    --verify "$VERIFY" \
    --restore-plan "$PLAN" \
    --approval-check "$APPROVAL" \
    --ids-health-evidence "$IDS_HEALTH" \
    --ids-model-audit "$TMP_DIR/missing_model_audit.json" \
    --ids-audit-gate "$TMP_DIR/missing_audit_gate.json" \
    --output "$OUTPUT" \
    --report "$REPORT" \
    --require-pass

python3 - "$OUTPUT" "$REPORT" <<'PY'
import json
import pathlib
import sys

bundle = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
report = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
rendered = json.dumps(bundle, sort_keys=True)
assert bundle['schema_version'] == 1
assert bundle['status'] == 'pass'
assert bundle['ok'] is True
assert bundle['safe_default'].startswith('read-only')
assert 'full JSON inputs are not embedded' in bundle['privacy_note']
assert 'must-not-leak' not in rendered
assert 'private_key' not in rendered
assert 'secret_token' not in rendered
assert 'signature' not in rendered
assert 'status=pass' in report
assert 'component=policy_verify|pass|' in report
PY

write_json "$VERIFY" '{"schema_version":1,"created_utc":"2026-06-26T00:00:01Z","decision":"restore_review","critical_findings":1,"warning_findings":0}'
if python3 host_vm_policy_evidence_bundle.py \
    --attestation "$ATTEST" \
    --verify "$VERIFY" \
    --restore-plan "$PLAN" \
    --approval-check "$APPROVAL" \
    --ids-health-evidence "$IDS_HEALTH" \
    --ids-model-audit "$TMP_DIR/missing_model_audit.json" \
    --ids-audit-gate "$TMP_DIR/missing_audit_gate.json" \
    --output "$OUTPUT" \
    --report "$REPORT" \
    --require-pass; then
    echo 'expected --require-pass to reject restore_review evidence' >&2
    exit 1
fi

python3 - "$OUTPUT" <<'PY'
import json
import pathlib
import sys

bundle = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert bundle['status'] == 'review'
assert bundle['ok'] is False
assert 'policy_verify' in bundle['review_items']
PY

echo '[static-check] host_vm_policy_evidence_bundle.py passed static behavior checks'
