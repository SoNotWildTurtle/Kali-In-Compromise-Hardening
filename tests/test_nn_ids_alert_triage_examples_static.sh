#!/usr/bin/env bash
# MINC - Static coverage for passive NN IDS alert triage examples.
# Defensive documentation validation only; does not inspect live IDS, host, VM, or hypervisor state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC="$ROOT_DIR/docs/nn_ids_alert_triage_examples.md"
CHANGELOG="$ROOT_DIR/changelog.d/nn_ids_alert_triage_examples.md"

[[ -f "$DOC" ]]
[[ -f "$CHANGELOG" ]]

# The examples must preserve the passive, aggregate-only safety boundary.
grep -q "aggregate-only evidence" "$DOC"
grep -q "analytical estimates, not certainty" "$DOC"
grep -q "human_review_required=true" "$DOC"
grep -q "live_action_authorized=false" "$DOC"
grep -q "no remediation, restore, retrain, firewall, service, or hypervisor action" "$DOC"
grep -q "no raw telemetry or secrets" "$DOC"

# Each supported triage decision should have a concrete synthetic record.
for decision in pass watch degraded blocked; do
  grep -q "## Example: $decision" "$DOC"
  grep -q "triage_decision=$decision" "$DOC"
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
  grep -q "$token" "$DOC"
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
  grep -q "$token" "$DOC"
done

grep -q "Fail closed" "$DOC"
grep -q "Accessibility and handoff notes" "$DOC"
grep -q "Compatibility and rollback" "$DOC"
grep -q "documentation-only" "$DOC"

# Changelog fragment must advertise additive documentation and the passive security boundary.
grep -q "nn_ids_alert_triage_examples.md" "$CHANGELOG"
grep -q "synthetic" "$CHANGELOG"
grep -q "documentation-only" "$CHANGELOG"
grep -q "does not inspect live IDS, host, VM, or hypervisor state" "$CHANGELOG"
grep -q "bash tests/test_nn_ids_alert_triage_examples_static.sh" "$CHANGELOG"
