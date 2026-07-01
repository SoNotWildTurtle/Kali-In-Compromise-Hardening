#!/usr/bin/env bash
# MINC - Static coverage for passive NN IDS alert triage examples.
# Defensive documentation validation only; does not inspect live IDS, host, VM, or hypervisor state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC="$ROOT_DIR/docs/nn_ids_alert_triage_examples.md"
CHANGELOG="$ROOT_DIR/changelog.d/nn_ids_alert_triage_examples.md"

fail() {
  printf '[triage-examples-static][FAIL] %s\n' "$*" >&2
  exit 1
}

[[ -f "$DOC" ]] || fail "missing required file: $DOC"
[[ -f "$CHANGELOG" ]] || fail "missing required file: $CHANGELOG"

require_doc() {
  local token="$1"
  grep -Fq -- "$token" "$DOC" || fail "documentation missing required token: $token"
}

require_changelog() {
  local token="$1"
  grep -Fq -- "$token" "$CHANGELOG" || fail "changelog missing required token: $token"
}

# The examples must preserve the passive, aggregate-only safety boundary.
for token in \
  "aggregate-only evidence" \
  "analytical estimates, not certainty" \
  "human_review_required=true" \
  "live_action_authorized=false" \
  "no remediation, restore, retrain, firewall, service, or hypervisor action" \
  "no raw telemetry or secrets"; do
  require_doc "$token"
done

# Each supported triage decision should have a concrete synthetic record.
for decision in pass watch degraded blocked; do
  require_doc "## Example: $decision"
  require_doc "triage_decision=$decision"
done

# Examples should remain useful for the current NN IDS evidence family and release handoffs.
for token in \
  "nn_ids_release_readiness_summary.json" \
  "nn_ids_release_readiness_summary.report" \
  "nn_ids_health_evidence.json" \
  "nn_ids_drift_evidence.json" \
  "nn_ids_drift_triage.md" \
  "nn_ids_model_card" \
  "nn_ids_posture_bundle_manifest.json"; do
  require_doc "$token"
done

# Records must keep stable handoff keys that future validators can enforce.
for token in \
  "release_ready=" \
  "source_artifacts=" \
  "artifact_hashes=" \
  "blocking_issues=" \
  "uncertainty_note=" \
  "privacy_scope=" \
  "rollback_reference=" \
  "next_evidence_needed=" \
  "owner="; do
  require_doc "$token"
done

for token in \
  "Fail closed" \
  "Accessibility and handoff notes" \
  "Compatibility and rollback" \
  "documentation-only"; do
  require_doc "$token"
done

# Changelog fragment must advertise additive documentation and the passive security boundary.
for token in \
  "nn_ids_alert_triage_examples.md" \
  "synthetic" \
  "documentation-only" \
  "does not inspect live IDS" \
  "host, VM, or hypervisor state" \
  "bash tests/test_nn_ids_alert_triage_examples_static.sh"; do
  require_changelog "$token"
done

printf '[triage-examples-static] NN IDS alert triage examples static checks passed\n'
