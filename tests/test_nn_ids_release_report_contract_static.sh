#!/usr/bin/env bash
# MINC - Static contract test for passive NN IDS release readiness key=value reports.
# Defensive validation only; uses synthetic JSON fixtures and does not inspect live IDS data.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/nn_ids_release_readiness_summary.py"
DOC="$ROOT_DIR/docs/nn_ids_release_readiness_summary.md"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"
grep -q "test_nn_ids_release_report_contract_static.sh" "$SCRIPT"
grep -q "Report contract" "$DOC"

cat > "$TMPDIR/model-audit.json" <<'JSON'
{
  "timestamp": "2026-06-30T00:00:00Z",
  "message": "nn_ids_model_audit_complete",
  "rows": 256,
  "features": ["duration", "bytes_in", "bytes_out", "packet_rate"],
  "metric_average": "binary",
  "metrics": {
    "accuracy": 0.95,
    "balanced_accuracy": 0.94,
    "precision": 0.93,
    "recall": 0.92,
    "f1": 0.925
  },
  "probability_available": true,
  "drift": {"max_mean_z": 0.7, "shifted_features": []},
  "robustness": {"robustness_index": 0.89}
}
JSON

cat > "$TMPDIR/audit-gate.json" <<'JSON'
{
  "timestamp": "2026-06-30T00:01:00Z",
  "message": "nn_ids_audit_gate_complete",
  "decision": "watch",
  "findings": [],
  "thresholds": {"auto_actions": false},
  "actions": []
}
JSON

python3 "$SCRIPT" \
  --model-audit "$TMPDIR/model-audit.json" \
  --audit-gate "$TMPDIR/audit-gate.json" \
  --output "$TMPDIR/ids-watch.json" \
  --report "$TMPDIR/ids-watch.report" \
  --strict >/dev/null

python3 - "$TMPDIR/ids-watch.json" "$TMPDIR/ids-watch.report" <<'PY'
import json
import sys

artifact = json.loads(open(sys.argv[1], encoding='utf-8').read())
report_lines = open(sys.argv[2], encoding='utf-8').read().splitlines()
report = {}
for line in report_lines:
    key, sep, value = line.partition('=')
    assert sep == '=', line
    if key != 'blocking_issue':
        assert key not in report, f'duplicate report key: {key}'
    report.setdefault(key, []).append(value)

required = {
    'created_utc',
    'decision',
    'ids_release_ready',
    'gate_decision',
    'blocking_issue_count',
    'changes_live_state',
    'reads_raw_telemetry',
    'aggregate_evidence_only',
    'schema_path',
    'safe_to_publish',
    'contains_raw_telemetry',
    'contains_secrets',
    'human_review_required',
}
missing = sorted(required - set(report))
assert not missing, missing
assert report['decision'] == [artifact['decision']], report
assert report['ids_release_ready'] == [str(artifact['ids_release_ready']).lower()], report
assert report['gate_decision'] == [artifact['audit_gate']['decision']], report
assert report['blocking_issue_count'] == [str(len(artifact['blocking_issues']))], report
assert report['changes_live_state'] == ['false'], report
assert report['reads_raw_telemetry'] == ['false'], report
assert report['aggregate_evidence_only'] == ['true'], report
assert report['schema_path'] == [artifact['evidence_manifest']['schema_path']], report
assert report['safe_to_publish'] == ['true'], report
assert report['contains_raw_telemetry'] == ['false'], report
assert report['contains_secrets'] == ['false'], report
assert report['human_review_required'] == ['true'], report
assert 'blocking_issue' not in report, report
PY

python3 - "$TMPDIR/audit-gate.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.loads(open(path, encoding='utf-8').read())
data['decision'] = 'retrain'
data['findings'] = [{'severity': 'high', 'reason': 'metric_drift'}]
open(path, 'w', encoding='utf-8').write(json.dumps(data))
PY

if python3 "$SCRIPT" \
  --model-audit "$TMPDIR/model-audit.json" \
  --audit-gate "$TMPDIR/audit-gate.json" \
  --output "$TMPDIR/ids-blocked.json" \
  --report "$TMPDIR/ids-blocked.report" \
  --strict >/dev/null; then
  echo "strict mode should fail closed for retrain gate decisions" >&2
  exit 1
fi

python3 - "$TMPDIR/ids-blocked.json" "$TMPDIR/ids-blocked.report" <<'PY'
import json
import sys

artifact = json.loads(open(sys.argv[1], encoding='utf-8').read())
report_lines = open(sys.argv[2], encoding='utf-8').read().splitlines()
blocking_lines = [line for line in report_lines if line.startswith('blocking_issue=')]
assert artifact['decision'] == 'ids_release_blocked', artifact
assert artifact['ids_release_ready'] is False, artifact
assert any('retrain' in issue for issue in artifact['blocking_issues']), artifact
assert any('retrain' in line for line in blocking_lines), report_lines
assert 'decision=ids_release_blocked' in report_lines, report_lines
assert 'ids_release_ready=false' in report_lines, report_lines
assert 'blocking_issue_count=1' in report_lines, report_lines
assert 'changes_live_state=false' in report_lines, report_lines
assert 'reads_raw_telemetry=false' in report_lines, report_lines
assert 'contains_secrets=false' in report_lines, report_lines
PY
