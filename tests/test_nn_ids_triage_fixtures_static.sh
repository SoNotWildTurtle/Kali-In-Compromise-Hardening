#!/usr/bin/env bash
# MINC - Static tests for passive NN IDS triage fixture examples.
# Defensive validation only; does not inspect live IDS, host, VM, or hypervisor state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT_DIR/nn_ids_triage_record_validate.sh"
PASS_FIXTURE="$ROOT_DIR/examples/nn_ids_triage_records/pass_release_ready.env"
WATCH_FIXTURE="$ROOT_DIR/examples/nn_ids_triage_records/watch_handoff.env"
DOC="$ROOT_DIR/docs/nn_ids_triage_record_validator.md"
CHANGELOG="$ROOT_DIR/changelog.d/nn_ids_triage_record_validator.md"

fail() {
  printf '[triage-fixtures-static][FAIL] %s\n' "$*" >&2
  exit 1
}

require_token() {
  local file="$1"
  local token="$2"
  grep -Fq -- "$token" "$file" || fail "$file missing required token: $token"
}

for file in "$VALIDATOR" "$PASS_FIXTURE" "$WATCH_FIXTURE" "$DOC" "$CHANGELOG"; do
  [[ -f "$file" ]] || fail "missing required file: $file"
done

for fixture in "$PASS_FIXTURE" "$WATCH_FIXTURE"; do
  require_token "$fixture" 'aggregate-only; no raw telemetry or secrets'
  require_token "$fixture" 'human_review_required=true'
  require_token "$fixture" 'live_action_authorized=false'
  require_token "$fixture" 'manifest:nn_ids_posture_bundle_manifest.json#sha256'
  require_token "$fixture" 'estimate'
  bash "$VALIDATOR" "$fixture" >/dev/null || fail "fixture should validate as passive handoff evidence: $fixture"
done

bash "$VALIDATOR" --release-gate "$PASS_FIXTURE" >/dev/null || fail 'release-ready pass fixture should pass release-gate mode'
if bash "$VALIDATOR" --release-gate "$WATCH_FIXTURE" >/dev/null 2>&1; then
  fail 'watch fixture must not pass release-gate mode until reviewer marks release_ready=true'
fi

for token in \
  'examples/nn_ids_triage_records/pass_release_ready.env' \
  'examples/nn_ids_triage_records/watch_handoff.env' \
  'fixture'; do
  require_token "$DOC" "$token"
  require_token "$CHANGELOG" "$token"
done

printf '[triage-fixtures-static] NN IDS triage fixture checks passed\n'
