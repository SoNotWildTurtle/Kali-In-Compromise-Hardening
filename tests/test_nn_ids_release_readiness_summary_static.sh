#!/usr/bin/env bash
# MINC - Static tests for passive NN IDS release readiness evidence.
# Defensive validation only; uses synthetic JSON fixtures and does not inspect live IDS data.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/nn_ids_release_readiness_summary.py"
SCHEMA="$ROOT_DIR/docs/schemas/nn_ids_release_readiness_summary.schema.json"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"

grep -q "ids_release_ready" "$SCRIPT"
grep -q "ids_release_blocked" "$SCRIPT"
grep -q "aggregate_evidence_only" "$SCRIPT"
grep -q "requires_human_review_before_release_promotion" "$SCRIPT"
grep -q "contains_secrets" "$SCRIPT"
grep -q '"changes_live_state": {"const": false}' "$SCHEMA"
grep -q '"reads_raw_telemetry": {"const": false}' "$SCHEMA"
grep -q '"aggregate_evidence_only": {"const": true}' "$SCHEMA"
grep -q '"schema_path": {"const": "docs/schemas/nn_ids_release_readiness_summary.schema.json"}' "$SCHEMA"

cat > "$TMPDIR/model-audit.json" <<'JSON'
{
  "timestamp": "2026-06-30T00:00:00Z",
  "message": "nn_ids_model_audit_complete",
  "model_path": "/opt/nnids/ids_model.pkl",
  "dataset_path": "/opt/nnids/datasets/dataset_clean.csv",
  "rows": 128,
  "features": ["duration", "bytes_in", "bytes_out"],
  "class_distribution": {"0": 64, "1": 64},
  "metric_average": "binary",
  "metrics": {
    "accuracy": 0.94,
    "balanced_accuracy": 0.93,
    "precision": 0.92,
    "recall": 0.91,
    "f1": 0.915,
    "confusion_matrix": [[31, 1], [2, 30]]
  },
  "probability_available": true,
  "drift": {"baseline_created": false, "max_mean_z": 0.8, "shifted_features": []},
  "robustness": {"robustness_index": 0.88, "perturbation_scores": []},
  "explainability": {"top_features": [{"feature": "duration", "importance": 0.2}], "importance_drift": {"baseline_created": false, "top_feature_changes": []}}
}
JSON

cat > "$TMPDIR/audit-gate.json" <<'JSON'
{
  "timestamp": "2026-06-30T00:01:00Z",
  "message": "nn_ids_audit_gate_complete",
  "decision": "accept",
  "findings": [],
  "state": {"last_decision": "accept", "previous_decision": "watch", "consecutive_retrain": 0, "escalated_to_restore": false},
  "thresholds": {
    "min_f1": 0.7,
    "min_balanced_accuracy": 0.7,
    "min_robustness_index": 0.65,
    "max_mean_z": 3.0,
    "max_shifted_features": 10,
    "max_consecutive_retrain": 2,
    "auto_actions": false
  },
  "actions": []
}
JSON

python3 "$SCRIPT" \
  --model-audit "$TMPDIR/model-audit.json" \
  --audit-gate "$TMPDIR/audit-gate.json" \
  --output "$TMPDIR/ids-ready.json" \
  --report "$TMPDIR/ids-ready.report" \
  --strict >/dev/null

python3 - "$TMPDIR/ids-ready.json" "$SCHEMA" <<'PY'
import json
import sys
artifact = json.loads(open(sys.argv[1], encoding='utf-8').read())
schema = json.loads(open(sys.argv[2], encoding='utf-8').read())
assert artifact['decision'] == 'ids_release_ready', artifact
assert artifact['ids_release_ready'] is True, artifact
assert artifact['blocking_issues'] == [], artifact
assert artifact['changes_live_state'] is False, artifact
assert artifact['reads_raw_telemetry'] is False, artifact
assert artifact['aggregate_evidence_only'] is True, artifact
assert artifact['model_audit']['message'] == 'nn_ids_model_audit_complete', artifact
assert artifact['model_audit']['feature_count'] == 3, artifact
assert artifact['model_audit']['f1'] == 0.915, artifact
assert artifact['model_audit']['robustness_index'] == 0.88, artifact
assert artifact['audit_gate']['message'] == 'nn_ids_audit_gate_complete', artifact
assert artifact['audit_gate']['decision'] == 'accept', artifact
assert artifact['audit_gate']['auto_actions'] is False, artifact
handoff = artifact['reviewer_handoff']
assert handoff['requires_human_review_before_release_promotion'] is True, artifact
assert 'accept' in handoff['acceptable_gate_decisions'], artifact
assert 'restore' in handoff['remediation_gate_decisions'], artifact
manifest = artifact['evidence_manifest']
assert manifest['schema_path'] == schema['properties']['evidence_manifest']['properties']['schema_path']['const'], artifact
assert manifest['safe_to_publish'] is True, artifact
assert manifest['contains_raw_telemetry'] is False, artifact
assert manifest['contains_secrets'] is False, artifact
assert manifest['live_state_validation_required'] is False, artifact
assert manifest['human_review_required'] is True, artifact
assert artifact['rollback']['live_state_rollback_required'] is False, artifact
PY

grep -q '^decision=ids_release_ready$' "$TMPDIR/ids-ready.report"
grep -q '^ids_release_ready=true$' "$TMPDIR/ids-ready.report"
grep -q '^gate_decision=accept$' "$TMPDIR/ids-ready.report"
grep -q '^schema_path=docs/schemas/nn_ids_release_readiness_summary.schema.json$' "$TMPDIR/ids-ready.report"
grep -q '^contains_secrets=false$' "$TMPDIR/ids-ready.report"

python3 - "$TMPDIR/audit-gate.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.loads(open(path, encoding='utf-8').read())
data['decision'] = 'restore'
data['findings'] = [{'severity': 'critical', 'reason': 'audit_failed'}]
open(path, 'w', encoding='utf-8').write(json.dumps(data))
PY

if python3 "$SCRIPT" \
  --model-audit "$TMPDIR/model-audit.json" \
  --audit-gate "$TMPDIR/audit-gate.json" \
  --output "$TMPDIR/ids-blocked.json" \
  --strict >/dev/null; then
  echo "strict mode should fail closed for restore gate decisions" >&2
  exit 1
fi

python3 - "$TMPDIR/ids-blocked.json" <<'PY'
import json
import sys
artifact = json.loads(open(sys.argv[1], encoding='utf-8').read())
assert artifact['decision'] == 'ids_release_blocked', artifact
assert artifact['ids_release_ready'] is False, artifact
assert any('restore' in issue for issue in artifact['blocking_issues']), artifact
assert artifact['changes_live_state'] is False, artifact
assert artifact['reads_raw_telemetry'] is False, artifact
assert artifact['evidence_manifest']['safe_to_publish'] is True, artifact
PY
