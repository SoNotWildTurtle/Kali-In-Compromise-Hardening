#!/usr/bin/env bash
# MINC - Static tests for passive NN IDS triage record validation.
# Defensive validation only; does not inspect live IDS, host, VM, or hypervisor state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT_DIR/nn_ids_triage_record_validate.sh"
DOC="$ROOT_DIR/docs/nn_ids_triage_record_validator.md"
CHANGELOG="$ROOT_DIR/changelog.d/nn_ids_triage_record_validator.md"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  printf '[triage-validator-static][FAIL] %s\n' "$*" >&2
  exit 1
}

[[ -f "$VALIDATOR" ]] || fail "missing validator: $VALIDATOR"
[[ -f "$DOC" ]] || fail "missing documentation: $DOC"
[[ -f "$CHANGELOG" ]] || fail "missing changelog: $CHANGELOG"

bash -n "$VALIDATOR" || fail 'validator has invalid Bash syntax'

require_token() {
  local file="$1"
  local token="$2"
  grep -Fq -- "$token" "$file" || fail "$file missing required token: $token"
}

for token in \
  'Usage: nn_ids_triage_record_validate.sh [--release-gate] <triage-record>' \
  'nn_ids_triage_record_validate.sh --print-template' \
  'print_template()' \
  'triage_decision' \
  'release_ready' \
  'source_artifacts' \
  'artifact_hashes' \
  'uncertainty_note' \
  'privacy_scope' \
  'human_review_required' \
  'live_action_authorized' \
  'rollback_reference' \
  'next_evidence_needed' \
  'owner' \
  'aggregate-only' \
  'no raw telemetry or secrets' \
  'release gate rejects triage_decision' \
  'does not inspect live IDS'; do
  require_token "$VALIDATOR" "$token"
done

for token in \
  'NN IDS Triage Record Validator' \
  '--print-template' \
  '--release-gate' \
  'Release-gate mode accepts only `pass` and `watch`' \
  'Triage records are evidence, not authority' \
  'Compatibility impact' \
  'Rollback' \
  'Follow-up work'; do
  require_token "$DOC" "$token"
done

for token in \
  'nn_ids_triage_record_validate.sh' \
  'dependency-free' \
  'passive' \
  'aggregate-only' \
  'live_action_authorized=false' \
  '--print-template' \
  'bash tests/test_nn_ids_triage_record_validator_static.sh'; do
  require_token "$CHANGELOG" "$token"
done

cat > "$TMP_DIR/pass.env" <<'EOF'
triage_decision=pass
release_ready=true
source_artifacts=nn_ids_release_readiness_summary.json,nn_ids_health_evidence.json,nn_ids_drift_evidence.json,nn_ids_model_card.md,nn_ids_posture_bundle_manifest.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none
uncertainty_note=aggregate metrics look release-ready, but this remains an analytical estimate that requires reviewer sign-off
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=confirm hosted release-gate checks remain green at merge time
owner=release-reviewer
EOF

bash "$VALIDATOR" "$TMP_DIR/pass.env" >/dev/null || fail 'valid pass record should be accepted'
bash "$VALIDATOR" --release-gate "$TMP_DIR/pass.env" >/dev/null || fail 'valid pass record should be accepted by release gate mode'

bash "$VALIDATOR" --print-template > "$TMP_DIR/template.env" || fail '--print-template should render a passive template'
require_token "$TMP_DIR/template.env" 'triage_decision=watch'
require_token "$TMP_DIR/template.env" 'release_ready=false'
require_token "$TMP_DIR/template.env" 'aggregate-only; no raw telemetry or secrets'
require_token "$TMP_DIR/template.env" 'human_review_required=true'
require_token "$TMP_DIR/template.env" 'live_action_authorized=false'
bash "$VALIDATOR" "$TMP_DIR/template.env" >/dev/null || fail 'printed template should validate as passive handoff evidence'
if bash "$VALIDATOR" --release-gate "$TMP_DIR/template.env" >/dev/null 2>&1; then
  fail 'printed template must not pass release-gate mode until reviewer marks release_ready=true'
fi
if bash "$VALIDATOR" --print-template "$TMP_DIR/pass.env" >/dev/null 2>&1; then
  fail '--print-template must not accept extra record paths'
fi

cat > "$TMP_DIR/degraded.env" <<'EOF'
triage_decision=degraded
release_ready=false
source_artifacts=nn_ids_drift_evidence.json,nn_ids_health_evidence.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=drift evidence exceeds threshold for synthetic_feature_group_alpha
uncertainty_note=aggregate drift signals are estimates and require review before promotion
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=privacy-safe drift explanation and hosted gate rerun
owner=model-reviewer
EOF

bash "$VALIDATOR" "$TMP_DIR/degraded.env" >/dev/null || fail 'degraded record should be valid handoff evidence'
if bash "$VALIDATOR" --release-gate "$TMP_DIR/degraded.env" >/dev/null 2>&1; then
  fail 'release gate mode must reject degraded records'
fi

cat > "$TMP_DIR/unsafe.env" <<'EOF'
triage_decision=pass
release_ready=true
source_artifacts=nn_ids_release_readiness_summary.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none
uncertainty_note=unsafe record still claims an estimate
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=true
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=none
owner=release-reviewer
EOF

if bash "$VALIDATOR" "$TMP_DIR/unsafe.env" >/dev/null 2>&1; then
  fail 'validator must reject live_action_authorized=true'
fi

cat > "$TMP_DIR/malformed.env" <<'EOF'
triage_decision=watch
release_ready=true
this line is not key value
source_artifacts=nn_ids_health_evidence.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none; freshness recheck required
uncertainty_note=watch remains an estimate
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=freshness check
owner=ids-maintainer
EOF

if bash "$VALIDATOR" "$TMP_DIR/malformed.env" >/dev/null 2>&1; then
  fail 'validator must reject malformed non-empty lines'
fi

printf '[triage-validator-static] NN IDS triage record validator checks passed\n'
