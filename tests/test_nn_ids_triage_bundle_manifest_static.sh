#!/usr/bin/env bash
# MINC - Static tests for passive NN IDS triage bundle manifests.
# Defensive validation only; does not inspect live IDS, host, VM, or hypervisor state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT_DIR/nn_ids_triage_record_validate.sh"
MANIFEST_HELPER="$ROOT_DIR/nn_ids_triage_bundle_manifest.py"
DOC="$ROOT_DIR/docs/nn_ids_triage_record_validator.md"
CHANGELOG="$ROOT_DIR/changelog.d/nn_ids_triage_record_validator.md"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  printf '[triage-bundle-manifest-static][FAIL] %s\n' "$*" >&2
  exit 1
}

require_token() {
  local file="$1"
  local token="$2"
  grep -Fq -- "$token" "$file" || fail "$file missing required token: $token"
}

[[ -f "$VALIDATOR" ]] || fail "missing validator: $VALIDATOR"
[[ -f "$MANIFEST_HELPER" ]] || fail "missing manifest helper: $MANIFEST_HELPER"
[[ -f "$DOC" ]] || fail "missing documentation: $DOC"
[[ -f "$CHANGELOG" ]] || fail "missing changelog: $CHANGELOG"

python3 -m py_compile "$MANIFEST_HELPER" || fail 'manifest helper has invalid Python syntax'

for token in \
  'nn_ids_triage_bundle_manifest' \
  'human_review_required' \
  'live_action_authorized' \
  'aggregate-only; no raw telemetry or secrets' \
  'release-ready' \
  'review-required' \
  'blocked' \
  'sha256' \
  'does not inspect live IDS'; do
  require_token "$MANIFEST_HELPER" "$token"
done

for token in \
  'triage bundle manifest' \
  'nn_ids_triage_bundle_manifest.py' \
  '--generated-at' \
  'review-required' \
  'live_action_authorized=false'; do
  require_token "$DOC" "$token"
done

for token in \
  'nn_ids_triage_bundle_manifest.py' \
  'passive' \
  'aggregate-only' \
  'tests/test_nn_ids_triage_bundle_manifest_static.sh'; do
  require_token "$CHANGELOG" "$token"
done

cat > "$TMP_DIR/pass.env" <<'EOF'
triage_decision=pass
release_ready=true
source_artifacts=nn_ids_release_readiness_summary.json,nn_ids_health_evidence.json,nn_ids_drift_evidence.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none
uncertainty_note=aggregate metrics look release-ready, but this remains an analytical estimate that requires reviewer sign-off
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=confirm hosted release gates stay green
owner=release-reviewer
EOF

cat > "$TMP_DIR/watch.env" <<'EOF'
triage_decision=watch
release_ready=false
source_artifacts=nn_ids_health_evidence.json,nn_ids_drift_evidence.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none; freshness review still pending
uncertainty_note=aggregate evidence is an estimate with freshness uncertainty
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=collect fresh hosted gates and confirm drift freshness
owner=ids-maintainer
EOF

bash "$VALIDATOR" --emit-json "$TMP_DIR/pass.env" > "$TMP_DIR/pass.json" || fail 'pass record should export to JSON'
bash "$VALIDATOR" --emit-json "$TMP_DIR/watch.env" > "$TMP_DIR/watch.json" || fail 'watch record should export to JSON'

python3 "$MANIFEST_HELPER" --generated-at '2026-07-01T20:00:00+00:00' "$TMP_DIR/pass.json" "$TMP_DIR/watch.json" > "$TMP_DIR/manifest.json" || fail 'manifest helper should aggregate valid triage JSON records'

python3 - "$TMP_DIR/manifest.json" <<'PY' || fail 'manifest should preserve passive release handoff boundaries'
import json
import pathlib
import sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
assert manifest['manifest_type'] == 'nn_ids_triage_bundle_manifest'
assert manifest['schema_version'] == 1
assert manifest['generated_at'] == '2026-07-01T20:00:00+00:00'
assert manifest['record_count'] == 2
assert manifest['overall_status'] == 'review-required'
assert manifest['decision_counts']['pass'] == 1
assert manifest['decision_counts']['watch'] == 1
assert manifest['decision_counts']['degraded'] == 0
assert manifest['decision_counts']['blocked'] == 0
assert manifest['release_ready_count'] == 1
assert manifest['blocking_record_count'] == 0
assert manifest['human_review_required'] is True
assert manifest['live_action_authorized'] is False
assert manifest['privacy_scope'] == 'aggregate-only; no raw telemetry or secrets'
assert len(manifest['records']) == 2
assert all('sha256' in record and len(record['sha256']) == 64 for record in manifest['records'])
assert manifest['records'][0]['triage_decision'] == 'pass'
assert manifest['records'][1]['triage_decision'] == 'watch'
PY

cat > "$TMP_DIR/unsafe.json" <<'EOF'
{
  "triage_decision": "pass",
  "release_ready": true,
  "source_artifacts": "nn_ids_release_readiness_summary.json",
  "artifact_hashes": "manifest:nn_ids_posture_bundle_manifest.json#sha256",
  "blocking_issues": "none",
  "uncertainty_note": "aggregate estimate",
  "privacy_scope": "aggregate-only; no raw telemetry or secrets",
  "human_review_required": true,
  "live_action_authorized": true,
  "rollback_reference": "docs/nn_ids_alert_triage_playbook.md#rollback",
  "next_evidence_needed": "none",
  "owner": "release-reviewer"
}
EOF

if python3 "$MANIFEST_HELPER" "$TMP_DIR/unsafe.json" >/dev/null 2>&1; then
  fail 'manifest helper must reject records that authorize live action'
fi

cat > "$TMP_DIR/extra.json" <<'EOF'
{
  "triage_decision": "watch",
  "release_ready": false,
  "source_artifacts": "nn_ids_health_evidence.json",
  "artifact_hashes": "manifest:nn_ids_posture_bundle_manifest.json#sha256",
  "blocking_issues": "none; review pending",
  "uncertainty_note": "aggregate estimate",
  "privacy_scope": "aggregate-only; no raw telemetry or secrets",
  "human_review_required": true,
  "live_action_authorized": false,
  "rollback_reference": "docs/nn_ids_alert_triage_playbook.md#rollback",
  "next_evidence_needed": "freshness review",
  "owner": "ids-maintainer",
  "raw_telemetry": "forbidden"
}
EOF

if python3 "$MANIFEST_HELPER" "$TMP_DIR/extra.json" >/dev/null 2>&1; then
  fail 'manifest helper must reject extra raw-data keys'
fi

printf '[triage-bundle-manifest-static] NN IDS triage bundle manifest checks passed\n'
