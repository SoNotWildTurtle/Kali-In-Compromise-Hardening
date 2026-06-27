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
assert manifest['freshness_policy']['enabled'] is False
assert len(manifest['artifacts']) == 6
assert all(artifact['sha256'] for artifact in manifest['artifacts'])
assert all('mtime_utc' in artifact for artifact in manifest['artifacts'])
assert all('age_seconds' in artifact for artifact in manifest['artifacts'])
assert 'raw logs' in manifest['privacy_note']
assert 'Host VM Firstboot Handoff Manifest' in markdown
assert 'Freshness gate: `disabled`' in markdown
assert 'policy_evidence_bundle_json' in markdown
PY

python3 host_vm_policy_firstboot_manifest.py \
  --bundle "$TMP_DIR/policy_evidence_bundle.json" \
  --bundle-report "$TMP_DIR/policy_evidence_bundle.report" \
  --receipt "$TMP_DIR/policy_evidence_bundle_receipt.json" \
  --receipt-markdown "$TMP_DIR/policy_evidence_bundle_receipt.md" \
  --handoff-index "$TMP_DIR/firstboot_handoff.json" \
  --handoff-markdown "$TMP_DIR/firstboot_handoff.md" \
  --manifest "$TMP_DIR/firstboot_manifest_fresh.json" \
  --markdown "$TMP_DIR/firstboot_manifest_fresh.md" \
  --max-artifact-age-minutes 60 \
  --require-ready

python3 - "$TMP_DIR/firstboot_manifest_fresh.json" "$TMP_DIR/firstboot_manifest_fresh.md" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert manifest['decision'] == 'approved'
assert manifest['freshness_policy']['enabled'] is True
assert manifest['freshness_policy']['max_artifact_age_minutes'] == 60.0
assert manifest['freshness_policy']['future_clock_skew_tolerance_seconds'] == 300
assert 'Freshness gate: `enabled`' in markdown
assert 'Maximum artifact age: `60.0` minutes' in markdown
assert 'mtime `' in markdown
PY

if python3 host_vm_policy_firstboot_manifest.py --max-artifact-age-minutes 0 >/tmp/firstboot_manifest_invalid.out 2>/tmp/firstboot_manifest_invalid.err; then
  echo 'expected non-positive --max-artifact-age-minutes to fail argument validation' >&2
  exit 1
fi
if ! grep -q -- '--max-artifact-age-minutes must be greater than 0' /tmp/firstboot_manifest_invalid.err; then
  echo 'expected invalid freshness threshold error message' >&2
  exit 1
fi

touch -d '2 hours ago' "$TMP_DIR/firstboot_handoff.md"

if python3 host_vm_policy_firstboot_manifest.py \
  --bundle "$TMP_DIR/policy_evidence_bundle.json" \
  --bundle-report "$TMP_DIR/policy_evidence_bundle.report" \
  --receipt "$TMP_DIR/policy_evidence_bundle_receipt.json" \
  --receipt-markdown "$TMP_DIR/policy_evidence_bundle_receipt.md" \
  --handoff-index "$TMP_DIR/firstboot_handoff.json" \
  --handoff-markdown "$TMP_DIR/firstboot_handoff.md" \
  --manifest "$TMP_DIR/firstboot_manifest_stale.json" \
  --markdown "$TMP_DIR/firstboot_manifest_stale.md" \
  --max-artifact-age-minutes 60 \
  --require-ready; then
  echo 'expected --require-ready to fail when firstboot handoff markdown is stale' >&2
  exit 1
fi

python3 - "$TMP_DIR/firstboot_manifest_stale.json" "$TMP_DIR/firstboot_manifest_stale.md" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert manifest['decision'] == 'deferred'
assert manifest['ok'] is False
assert manifest['release_gate'] == 'stop'
assert any(blocker.startswith('firstboot_handoff_markdown:stale:') for blocker in manifest['blockers'])
assert 'Freshness gate: `enabled`' in markdown
assert 'firstboot_handoff_markdown:stale:' in markdown
PY

touch "$TMP_DIR/firstboot_handoff.md"
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
