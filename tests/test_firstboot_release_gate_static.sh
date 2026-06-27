#!/usr/bin/env bash
# MINC - Static tests for the firstboot release gate helper.
# Defensive validation only: verifies aggregate release evidence without changing state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

python3 -m py_compile firstboot_release_gate.py

cat > "$TMP_DIR/firstboot_manifest.json" <<'JSON'
{
  "schema_version": 1,
  "component": "host_vm_policy_firstboot_manifest",
  "created_utc": "2026-06-27T12:00:00Z",
  "ok": true,
  "decision": "approved",
  "release_gate": "pass",
  "blockers": []
}
JSON
cat > "$TMP_DIR/nn_ids_model_card.json" <<'JSON'
{
  "schema_version": 1,
  "component": "nn_ids_model_card",
  "generated_at": "2026-06-27T12:00:00+00:00",
  "ok": true,
  "status": "pass",
  "blockers": []
}
JSON

python3 firstboot_release_gate.py \
  --firstboot-manifest "$TMP_DIR/firstboot_manifest.json" \
  --model-card "$TMP_DIR/nn_ids_model_card.json" \
  --output "$TMP_DIR/release_gate.json" \
  --markdown "$TMP_DIR/release_gate.md" \
  --summary "$TMP_DIR/release_gate.summary.env" \
  --require-pass

python3 - "$TMP_DIR/release_gate.json" "$TMP_DIR/release_gate.md" "$TMP_DIR/release_gate.summary.env" <<'PY'
import json
import pathlib
import sys

gate = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
summary = pathlib.Path(sys.argv[3]).read_text(encoding='utf-8')
assert gate['component'] == 'firstboot_release_gate'
assert gate['ok'] is True
assert gate['decision'] == 'approved'
assert gate['release_gate'] == 'pass'
assert gate['blockers'] == []
assert len(gate['artifacts']) == 2
assert all(artifact['sha256'] for artifact in gate['artifacts'])
assert 'raw logs' in gate['privacy_note']
assert 'model binaries' in gate['privacy_note']
assert 'Firstboot Release Gate' in markdown
assert 'host_vm_firstboot' in markdown
assert 'nn_ids_model_card' in markdown
assert 'Safety, privacy, and rollback' in markdown
expected_summary = {
    'FIRSTBOOT_RELEASE_GATE_SCHEMA_VERSION="1"',
    'FIRSTBOOT_RELEASE_GATE_COMPONENT="firstboot_release_gate"',
    'FIRSTBOOT_RELEASE_GATE_OK="true"',
    'FIRSTBOOT_RELEASE_GATE_DECISION="approved"',
    'FIRSTBOOT_RELEASE_GATE_STATUS="pass"',
    'FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT="0"',
    'FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT="2"',
    'FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT="0"',
    'FIRSTBOOT_RELEASE_GATE_PRIVACY_SCOPE="aggregate_only"',
}
summary_lines = set(summary.splitlines())
missing = expected_summary - summary_lines
assert not missing, missing
assert any(line.startswith('FIRSTBOOT_RELEASE_GATE_CREATED_UTC="') for line in summary_lines)
for banned in ['raw logs', 'packets', 'captures', 'credentials', 'hostnames', 'usernames', 'secrets', 'model binaries', 'datasets']:
    assert banned not in summary
PY

cat > "$TMP_DIR/nn_ids_model_card.json" <<'JSON'
{
  "schema_version": 1,
  "component": "nn_ids_model_card",
  "generated_at": "2026-06-27T12:00:00+00:00",
  "ok": false,
  "status": "fail",
  "blockers": ["drift_evidence.fail"]
}
JSON

if python3 firstboot_release_gate.py \
  --firstboot-manifest "$TMP_DIR/firstboot_manifest.json" \
  --model-card "$TMP_DIR/nn_ids_model_card.json" \
  --output "$TMP_DIR/release_gate_fail.json" \
  --markdown "$TMP_DIR/release_gate_fail.md" \
  --summary "$TMP_DIR/release_gate_fail.summary.env" \
  --require-pass; then
  echo 'expected --require-pass to fail when the NN IDS model card is not ready' >&2
  exit 1
fi

python3 - "$TMP_DIR/release_gate_fail.json" "$TMP_DIR/release_gate_fail.md" "$TMP_DIR/release_gate_fail.summary.env" <<'PY'
import json
import pathlib
import sys

gate = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
summary = pathlib.Path(sys.argv[3]).read_text(encoding='utf-8')
assert gate['ok'] is False
assert gate['decision'] == 'deferred'
assert gate['release_gate'] == 'stop'
assert 'nn_ids_model_card_not_ready' in gate['blockers']
assert 'nn_ids_model_card_status:fail' in gate['blockers']
assert 'Regenerate NN IDS schema' in markdown
assert 'FIRSTBOOT_RELEASE_GATE_OK="false"' in summary
assert 'FIRSTBOOT_RELEASE_GATE_DECISION="deferred"' in summary
assert 'FIRSTBOOT_RELEASE_GATE_STATUS="stop"' in summary
assert 'FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT="2"' in summary
PY

rm "$TMP_DIR/nn_ids_model_card.json"
if python3 firstboot_release_gate.py \
  --firstboot-manifest "$TMP_DIR/firstboot_manifest.json" \
  --model-card "$TMP_DIR/nn_ids_model_card.json" \
  --output "$TMP_DIR/release_gate_missing.json" \
  --markdown "$TMP_DIR/release_gate_missing.md" \
  --require-pass; then
  echo 'expected --require-pass to fail when the model card is missing' >&2
  exit 1
fi
python3 - "$TMP_DIR/release_gate_missing.json" <<'PY'
import json
import pathlib
import sys

gate = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert any(blocker.startswith('missing:') for blocker in gate['blockers'])
assert gate['inputs']['nn_ids_model_card']['status'] == 'unknown'
PY

if python3 firstboot_release_gate.py --max-artifact-age-minutes 0 >/tmp/firstboot_release_gate_invalid.out 2>/tmp/firstboot_release_gate_invalid.err; then
  echo 'expected non-positive --max-artifact-age-minutes to fail argument validation' >&2
  exit 1
fi
if ! grep -q -- '--max-artifact-age-minutes must be greater than 0' /tmp/firstboot_release_gate_invalid.err; then
  echo 'expected invalid freshness threshold error message' >&2
  exit 1
fi

python3 firstboot_release_gate.py \
  --firstboot-manifest "$TMP_DIR/firstboot_manifest.json" \
  --model-card "$TMP_DIR/nn_ids_model_card.json" \
  --output "$TMP_DIR/release_gate_no_summary.json" \
  --markdown "$TMP_DIR/release_gate_no_summary.md" \
  --summary '' >/tmp/firstboot_release_gate_no_summary.out || true
if [[ -e "$TMP_DIR/release_gate_no_summary.summary.env" ]]; then
  echo 'expected empty --summary to disable summary generation' >&2
  exit 1
fi

if ! grep -q 'firstboot_release_gate.py' build_custom_iso.sh; then
  echo 'expected firstboot_release_gate.py to be packaged into the custom ISO' >&2
  exit 1
fi
if ! grep -q -- '--summary /var/log/firstboot_release_gate.summary.env' firstboot_release_gate.service; then
  echo 'expected firstboot_release_gate.service to write the operator summary artifact' >&2
  exit 1
fi

if ! grep -q -- '--summary' firstboot_release_gate.py; then
  echo 'expected firstboot_release_gate.py to expose --summary' >&2
  exit 1
fi

echo '[static-check] firstboot_release_gate.py passed static behavior checks'
