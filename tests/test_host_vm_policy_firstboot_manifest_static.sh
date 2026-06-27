#!/usr/bin/env bash
# MINC - Static tests for the host/VM firstboot manifest helper.
# Defensive validation only: verifies privacy-safe artifact manifest behavior.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

python3 -m py_compile host_vm_policy_firstboot_manifest.py

cat > "$TMP_DIR/policy_evidence_bundle.json" <<'JSON'
{"schema_version": 1, "overall_status": "pass", "components": []}
JSON
cat > "$TMP_DIR/policy_evidence_bundle.report" <<'EOF'
policy evidence bundle: pass
EOF
cat > "$TMP_DIR/policy_evidence_bundle_receipt.json" <<'JSON'
{"schema_version": 1, "ok": true, "decision": "approved", "release_gate": "pass", "bundle_status": "pass"}
JSON
cat > "$TMP_DIR/policy_evidence_bundle_receipt.md" <<'EOF'
# Receipt
approved
EOF
cat > "$TMP_DIR/firstboot_handoff.json" <<'JSON'
{"schema_version": 1, "component": "host_vm_policy_firstboot_handoff", "ok": true, "decision": "approved", "release_gate": "pass", "bundle_status": "pass"}
JSON
cat > "$TMP_DIR/firstboot_handoff.md" <<'EOF'
# Host VM Firstboot Policy Handoff
approved
EOF

python3 host_vm_policy_firstboot_manifest.py \
  --bundle "$TMP_DIR/policy_evidence_bundle.json" \
  --bundle-report "$TMP_DIR/policy_evidence_bundle.report" \
  --receipt "$TMP_DIR/policy_evidence_bundle_receipt.json" \
  --receipt-markdown "$TMP_DIR/policy_evidence_bundle_receipt.md" \
  --handoff-index "$TMP_DIR/firstboot_handoff.json" \
  --handoff-markdown "$TMP_DIR/firstboot_handoff.md" \
  --manifest "$TMP_DIR/firstboot_manifest.json" \
  --markdown "$TMP_DIR/firstboot_manifest.md" \
  --require-ready

python3 - "$TMP_DIR/firstboot_manifest.json" "$TMP_DIR/firstboot_manifest.md" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert manifest['component'] == 'host_vm_policy_firstboot_manifest'
assert manifest['decision'] == 'approved'
assert manifest['ok'] is True
assert manifest['release_gate'] == 'pass'
assert manifest['blockers'] == []
assert len(manifest['artifacts']) == 6
assert all(artifact['sha256'] for artifact in manifest['artifacts'])
assert 'raw logs' in manifest['privacy_note']
assert 'Host VM Firstboot Handoff Manifest' in markdown
assert 'policy_evidence_bundle_json' in markdown
PY

rm "$TMP_DIR/firstboot_handoff.md"

if python3 host_vm_policy_firstboot_manifest.py \
  --bundle "$TMP_DIR/policy_evidence_bundle.json" \
  --bundle-report "$TMP_DIR/policy_evidence_bundle.report" \
  --receipt "$TMP_DIR/policy_evidence_bundle_receipt.json" \
  --receipt-markdown "$TMP_DIR/policy_evidence_bundle_receipt.md" \
  --handoff-index "$TMP_DIR/firstboot_handoff.json" \
  --handoff-markdown "$TMP_DIR/firstboot_handoff.md" \
  --manifest "$TMP_DIR/firstboot_manifest.json" \
  --markdown "$TMP_DIR/firstboot_manifest.md" \
  --require-ready; then
  echo 'expected --require-ready to fail when required handoff markdown is missing' >&2
  exit 1
fi

python3 - "$TMP_DIR/firstboot_manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert manifest['decision'] == 'deferred'
assert manifest['ok'] is False
assert manifest['release_gate'] == 'stop'
assert 'firstboot_handoff_markdown' in manifest['blockers']
PY

cat > "$TMP_DIR/firstboot_handoff.json" <<'JSON'
{"schema_version": 1, "component": "host_vm_policy_firstboot_handoff", "ok": false, "decision": "deferred", "release_gate": "stop", "bundle_status": "restore_review"}
JSON
cat > "$TMP_DIR/firstboot_handoff.md" <<'EOF'
# Host VM Firstboot Policy Handoff
deferred
EOF

if python3 host_vm_policy_firstboot_manifest.py \
  --bundle "$TMP_DIR/policy_evidence_bundle.json" \
  --bundle-report "$TMP_DIR/policy_evidence_bundle.report" \
  --receipt "$TMP_DIR/policy_evidence_bundle_receipt.json" \
  --receipt-markdown "$TMP_DIR/policy_evidence_bundle_receipt.md" \
  --handoff-index "$TMP_DIR/firstboot_handoff.json" \
  --handoff-markdown "$TMP_DIR/firstboot_handoff.md" \
  --manifest "$TMP_DIR/firstboot_manifest.json" \
  --markdown "$TMP_DIR/firstboot_manifest.md" \
  --require-ready; then
  echo 'expected --require-ready to fail when firstboot handoff is deferred' >&2
  exit 1
fi

python3 - "$TMP_DIR/firstboot_manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert manifest['decision'] == 'deferred'
assert 'firstboot_handoff_not_ready' in manifest['blockers']
assert manifest['bundle_status'] == 'restore_review'
PY

echo '[static-check] host_vm_policy_firstboot_manifest.py passed static behavior checks'
