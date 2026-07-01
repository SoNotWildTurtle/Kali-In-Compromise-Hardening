#!/usr/bin/env bash
# MINC - Dependency-free schema conformance checks for NN IDS release readiness artifacts.
# Defensive validation only; uses synthetic artifacts and does not inspect live IDS, packet, model, or host state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$ROOT_DIR/docs/schemas/nn_ids_release_readiness_summary.schema.json"
SCRIPT="$ROOT_DIR/nn_ids_release_readiness_summary.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/model-audit.json" <<'JSON'
{
  "timestamp": "2026-06-30T00:00:00Z",
  "message": "nn_ids_model_audit_complete",
  "rows": 256,
  "features": ["duration", "bytes_in", "bytes_out", "packet_count"],
  "metric_average": "binary",
  "metrics": {
    "accuracy": 0.96,
    "balanced_accuracy": 0.95,
    "precision": 0.94,
    "recall": 0.93,
    "f1": 0.935
  },
  "probability_available": true,
  "drift": {"max_mean_z": 0.7, "shifted_features": []},
  "robustness": {"robustness_index": 0.9}
}
JSON

cat > "$TMPDIR/audit-gate.json" <<'JSON'
{
  "timestamp": "2026-06-30T00:01:00Z",
  "message": "nn_ids_audit_gate_complete",
  "decision": "watch",
  "findings": [{"severity": "info", "reason": "watching_drift"}],
  "thresholds": {"auto_actions": false},
  "actions": []
}
JSON

python3 "$SCRIPT" \
  --model-audit "$TMPDIR/model-audit.json" \
  --audit-gate "$TMPDIR/audit-gate.json" \
  --output "$TMPDIR/ids-watch-ready.json" \
  --strict >/dev/null

python3 - "$TMPDIR/audit-gate.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.loads(open(path, encoding='utf-8').read())
data['decision'] = 'retrain'
data['findings'] = [{'severity': 'high', 'reason': 'model_quality_degraded'}]
open(path, 'w', encoding='utf-8').write(json.dumps(data))
PY

if python3 "$SCRIPT" \
  --model-audit "$TMPDIR/model-audit.json" \
  --audit-gate "$TMPDIR/audit-gate.json" \
  --output "$TMPDIR/ids-retrain-blocked.json" \
  --strict >/dev/null; then
  echo "strict mode should fail closed for retrain gate decisions" >&2
  exit 1
fi

python3 - "$SCHEMA" "$TMPDIR/ids-watch-ready.json" "$TMPDIR/ids-retrain-blocked.json" <<'PY'
import json
import sys
from pathlib import Path

schema = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
artifacts = [json.loads(Path(path).read_text(encoding='utf-8')) for path in sys.argv[2:]]
errors = []


def at_path(document, dotted):
    node = document
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            raise KeyError(dotted)
        node = node[part]
    return node


def require(condition, message):
    if not condition:
        errors.append(message)


required_top = schema.get('required', [])
for artifact in artifacts:
    decision = artifact.get('decision')
    for key in required_top:
        require(key in artifact, f'{decision}: missing required top-level key {key}')

    constants = {
        'schema_version': schema['properties']['schema_version']['const'],
        'summary': schema['properties']['summary']['const'],
        'changes_live_state': schema['properties']['changes_live_state']['const'],
        'reads_raw_telemetry': schema['properties']['reads_raw_telemetry']['const'],
        'aggregate_evidence_only': schema['properties']['aggregate_evidence_only']['const'],
        'model_audit.message': schema['properties']['model_audit']['properties']['message']['const'],
        'audit_gate.message': schema['properties']['audit_gate']['properties']['message']['const'],
        'audit_gate.auto_actions': schema['properties']['audit_gate']['properties']['auto_actions']['const'],
        'evidence_manifest.schema_path': schema['properties']['evidence_manifest']['properties']['schema_path']['const'],
        'evidence_manifest.safe_to_publish': schema['properties']['evidence_manifest']['properties']['safe_to_publish']['const'],
        'evidence_manifest.contains_raw_telemetry': schema['properties']['evidence_manifest']['properties']['contains_raw_telemetry']['const'],
        'evidence_manifest.contains_secrets': schema['properties']['evidence_manifest']['properties']['contains_secrets']['const'],
        'evidence_manifest.live_state_validation_required': schema['properties']['evidence_manifest']['properties']['live_state_validation_required']['const'],
        'evidence_manifest.human_review_required': schema['properties']['evidence_manifest']['properties']['human_review_required']['const'],
        'rollback.live_state_rollback_required': schema['properties']['rollback']['properties']['live_state_rollback_required']['const'],
    }
    for dotted, expected in constants.items():
        try:
            actual = at_path(artifact, dotted)
        except KeyError:
            errors.append(f'{decision}: missing constant path {dotted}')
            continue
        require(actual == expected, f'{decision}: {dotted}={actual!r}, expected {expected!r}')

    enum = schema['properties']['decision']['enum']
    require(decision in enum, f'{decision}: decision is outside schema enum')
    gate_enum = schema['properties']['audit_gate']['properties']['decision']['enum']
    require(artifact['audit_gate']['decision'] in gate_enum, f'{decision}: audit gate decision outside schema enum')

    for metric in ['accuracy', 'balanced_accuracy', 'precision', 'recall', 'f1', 'robustness_index']:
        value = artifact['model_audit'][metric]
        require(isinstance(value, (int, float)), f'{decision}: {metric} is not numeric')
        require(0 <= value <= 1, f'{decision}: {metric} is outside [0, 1]')

    require(artifact['model_audit']['rows'] >= 1, f'{decision}: rows must be positive')
    require(artifact['model_audit']['feature_count'] >= 1, f'{decision}: feature_count must be positive')
    require(artifact['model_audit']['shifted_feature_count'] >= 0, f'{decision}: shifted_feature_count must be non-negative')
    require(isinstance(artifact['evidence_manifest']['static_validation_commands'], list), f'{decision}: static validation commands must be a list')
    require('bash tests/test_nn_ids_release_schema_contract_static.sh' in artifact['evidence_manifest']['static_validation_commands'], f'{decision}: schema contract test command missing from manifest')
    require('Static Security Checks' in artifact['evidence_manifest']['hosted_required_checks'], f'{decision}: hosted Static Security Checks missing')

ready = artifacts[0]
blocked = artifacts[1]
require(ready['decision'] == 'ids_release_ready', 'watch artifact should be release-ready')
require(ready['ids_release_ready'] is True, 'ready artifact should set ids_release_ready=true')
require(ready['blocking_issues'] == [], 'ready artifact should have no blocking issues')
require(blocked['decision'] == 'ids_release_blocked', 'retrain artifact should be blocked')
require(blocked['ids_release_ready'] is False, 'blocked artifact should set ids_release_ready=false')
require(len(blocked['blocking_issues']) >= 1, 'blocked artifact should include blocking issues')
require(any('retrain' in issue for issue in blocked['blocking_issues']), 'blocked artifact should name retrain as a blocker')

if errors:
    for error in errors:
        print(f'[schema-contract][FAIL] {error}', file=sys.stderr)
    sys.exit(1)
print('[schema-contract] NN IDS release readiness artifacts satisfy dependency-free schema contract checks')
PY
