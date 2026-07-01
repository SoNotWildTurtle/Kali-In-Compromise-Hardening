#!/usr/bin/env bash
# MINC - Static coverage for the passive NN IDS alert triage playbook.
# Defensive documentation validation only; does not inspect live IDS, host, or VM state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC="$ROOT_DIR/docs/nn_ids_alert_triage_playbook.md"
CHANGELOG="$ROOT_DIR/changelog.d/nn_ids_alert_triage_playbook.md"

[[ -f "$DOC" ]]
[[ -f "$CHANGELOG" ]]

# The playbook must preserve passive safety and privacy boundaries.
grep -q "aggregate-only" "$DOC"
grep -q "does not authorize operational targeting" "$DOC"
grep -q "live_action_authorized=false" "$DOC"
grep -q "human_review_required=true" "$DOC"
grep -q "Do not run live remediation" "$DOC"
grep -q "not certainty" "$DOC"
grep -q "contains raw telemetry/secrets" "$DOC"

# The playbook should connect current NN IDS evidence families without changing runtime behavior.
for token in \
  "nn_ids_health_evidence.json" \
  "nn_ids_drift_evidence.json" \
  "nn_ids_drift_triage" \
  "nn_ids_posture_bundle_manifest" \
  "nn_ids_model_card" \
  "nn_ids_release_readiness_summary.json" \
  "nn_ids_release_readiness_summary.report"; do
  grep -q "$token" "$DOC"
done

# Triage categories must be stable and conservative for release gates.
for token in "pass" "watch" "degraded" "blocked"; do
  grep -q "\`$token\`" "$DOC"
done

grep -q "fail closed" "$DOC"
grep -q "Accessibility and handoff guidance" "$DOC"
grep -q "Rollback" "$DOC"

# Changelog fragment must advertise the additive documentation and passive security boundary.
grep -q "nn_ids_alert_triage_playbook.md" "$CHANGELOG"
grep -q "passive NN IDS alert triage playbook" "$CHANGELOG"
grep -q "does not read packets, payloads, raw telemetry, secrets, live host state, VM state, or hypervisor state" "$CHANGELOG"
grep -q "bash tests/test_nn_ids_alert_triage_playbook_static.sh" "$CHANGELOG"
