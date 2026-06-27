#!/usr/bin/env bash
# MINC - Static tests for the host/VM policy evidence receipt gate.
# Defensive validation only: verifies approval/deferred behavior and privacy boundaries.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BUNDLE="$TMP_DIR/policy_evidence_bundle.json"
RECEIPT="$TMP_DIR/receipt.json"
MARKDOWN="$TMP_DIR/receipt.md"

python3 -m py_compile host_vm_policy_evidence_bundle_receipt.py

cat > "$BUNDLE" <<'JSON'
{
  "schema_version": 1,
  "status": "pass",
  "ok": true,
  "review_items": [],
  "components": [
    {"name": "policy_verify", "status": "pass", "required": true},
    {"name": "nn_ids_health_evidence", "status": "pass", "required": false}
  ],
  "secret_token": "must-not-leak"
}
JSON

python3 host_vm_policy_evidence_bundle_receipt.py \
  --bundle "$BUNDLE" \
  --output "$RECEIPT" \
  --markdown "$MARKDOWN" \
  --require-ready

python3 - "$RECEIPT" "$MARKDOWN" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
rendered = json.dumps(receipt, sort_keys=True) + markdown
assert receipt['schema_version'] == 1
assert receipt['decision'] == 'approved'
assert receipt['ok'] is True
assert receipt['release_gate'] == 'pass'
assert receipt['bundle_status'] == 'pass'
assert receipt['bundle_sha256']
assert 'policy_verify' in rendered
assert 'raw logs' in receipt['privacy_note']
assert 'must-not-leak' not in rendered
assert 'secret_token' not in rendered
assert 'Decision: `approved`' in markdown
PY

cat > "$BUNDLE" <<'JSON'
{
  "schema_version": 1,
  "status": "review",
  "ok": false,
  "review_items": ["policy_verify"],
  "components": [
    {"name": "policy_verify", "status": "review", "required": true}
  ]
}
JSON

if python3 host_vm_policy_evidence_bundle_receipt.py \
  --bundle "$BUNDLE" \
  --output "$RECEIPT" \
  --markdown "$MARKDOWN" \
  --require-ready; then
  echo 'expected --require-ready to reject review bundle' >&2
  exit 1
fi

python3 - "$RECEIPT" "$MARKDOWN" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert receipt['decision'] == 'deferred'
assert receipt['ok'] is False
assert receipt['release_gate'] == 'stop'
assert 'policy_verify' in receipt['review_items']
assert 'Do not promote' in '\n'.join(receipt['action_items'])
assert 'Decision: `deferred`' in markdown
PY

cat > "$BUNDLE" <<'JSON'
{
  "schema_version": 1,
  "status": "warn",
  "ok": false,
  "review_items": ["nn_ids_health_evidence"],
  "components": [
    {"name": "nn_ids_health_evidence", "status": "warn", "required": false}
  ]
}
JSON

if python3 host_vm_policy_evidence_bundle_receipt.py \
  --bundle "$BUNDLE" \
  --output "$RECEIPT" \
  --markdown "$MARKDOWN" \
  --require-ready; then
  echo 'expected warning bundle to defer without explicit allowance' >&2
  exit 1
fi

python3 host_vm_policy_evidence_bundle_receipt.py \
  --bundle "$BUNDLE" \
  --output "$RECEIPT" \
  --markdown "$MARKDOWN" \
  --allow-warning-approval \
  --require-ready

python3 - "$RECEIPT" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert receipt['decision'] == 'approved'
assert receipt['bundle_status'] == 'warn'
assert receipt['allow_warning_approval'] is True
PY

if python3 host_vm_policy_evidence_bundle_receipt.py \
  --bundle "$TMP_DIR/missing.json" \
  --output "$RECEIPT" \
  --markdown "$MARKDOWN" \
  --require-ready; then
  echo 'expected missing bundle to defer' >&2
  exit 1
fi

python3 - "$RECEIPT" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert receipt['decision'] == 'deferred'
assert receipt['bundle_status'] == 'missing'
assert 'missing_bundle' in receipt['review_items']
PY

echo '[static-check] host_vm_policy_evidence_bundle_receipt.py passed static behavior checks'
