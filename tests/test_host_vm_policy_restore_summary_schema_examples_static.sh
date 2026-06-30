#!/usr/bin/env bash
# MINC - Static schema example validation for passive restore release summary evidence.
# Defensive test only: validates synthetic aggregate JSON fixtures without touching live policy.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_policy_restore_release_summary.py"
SCHEMA="$ROOT_DIR/docs/schemas/host_vm_policy_restore_release_summary.schema.json"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m json.tool "$SCHEMA" >/dev/null
python3 -m py_compile "$SCRIPT"

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$TMPDIR/ready.json" "$TMPDIR/blocked.json" "$NOW" <<'PY'
import json, sys
ready_path, blocked_path, now = sys.argv[1:]
ready = {
    'schema_version': 1,
    'created_utc': now,
    'mode': 'dry_run',
    'decision': 'restore_ready_dry_run',
    'changes_live_state': False,
    'requires_manual_invocation': True,
    'issues': [],
    'safe_default': 'dry-run unless --execute is passed and approval validation is fresh and valid',
    'actions': [{'name': 'host_vm_comm_guard.conf', 'target': '/etc/host_vm_comm_guard.conf', 'status': 'preflight_ok'}],
}
blocked = {
    'schema_version': 1,
    'created_utc': now,
    'mode': 'dry_run',
    'decision': 'restore_blocked',
    'changes_live_state': False,
    'requires_manual_invocation': True,
    'issues': ['approval check decision must be approval_valid'],
    'actions': [],
}
json.dump(ready, open(ready_path, 'w'))
json.dump(blocked, open(blocked_path, 'w'))
PY

python3 "$SCRIPT" "$TMPDIR/ready.json" \
    --expected-blocked-result "$TMPDIR/blocked.json" \
    --output "$TMPDIR/summary-ready.json" \
    --report "$TMPDIR/summary-ready.report" \
    --strict >/dev/null

python3 - "$TMPDIR/ready.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data['issues'] = ['synthetic blocker for schema example coverage']
json.dump(data, open(path, 'w'))
PY

if python3 "$SCRIPT" "$TMPDIR/ready.json" \
    --expected-blocked-result "$TMPDIR/blocked.json" \
    --output "$TMPDIR/summary-blocked.json" \
    --report "$TMPDIR/summary-blocked.report" \
    --strict >/dev/null 2>&1; then
    echo "strict summary must fail for blocked schema example coverage" >&2
    exit 1
fi

python3 - "$SCHEMA" "$TMPDIR/summary-ready.json" "$TMPDIR/summary-blocked.json" <<'PY'
import json, sys
from pathlib import Path

schema_path, ready_path, blocked_path = map(Path, sys.argv[1:])
schema = json.loads(schema_path.read_text(encoding='utf-8'))
ready = json.loads(ready_path.read_text(encoding='utf-8'))
blocked = json.loads(blocked_path.read_text(encoding='utf-8'))

required = set(schema['required'])
properties = schema['properties']
expected_required = {
    'schema_version',
    'created_utc',
    'decision',
    'summary_ready',
    'ready_restore_decision',
    'expected_blocked_decision',
    'blocking_issues',
    'changes_live_state',
    'reads_raw_telemetry',
    'aggregate_evidence_only',
    'requires_manual_invocation',
    'safe_default',
    'reviewer_handoff',
}
assert required == expected_required, required
assert set(ready) == required, ready
assert set(blocked) == required, blocked
assert schema['additionalProperties'] is False

for summary in (ready, blocked):
    assert summary['schema_version'] == properties['schema_version']['const']
    assert summary['changes_live_state'] == properties['changes_live_state']['const'] is False
    assert summary['reads_raw_telemetry'] == properties['reads_raw_telemetry']['const'] is False
    assert summary['aggregate_evidence_only'] == properties['aggregate_evidence_only']['const'] is True
    assert summary['requires_manual_invocation'] == properties['requires_manual_invocation']['const'] is True
    assert summary['safe_default'] == properties['safe_default']['const']
    assert summary['reviewer_handoff']['confirm_no_live_state_change'] is True
    assert summary['reviewer_handoff']['confirm_manual_restore_only'] is True

assert ready['decision'] == 'restore_summary_ready', ready
assert ready['summary_ready'] is True, ready
assert ready['blocking_issues'] == [], ready
assert blocked['decision'] == 'restore_summary_blocked', blocked
assert blocked['summary_ready'] is False, blocked
assert blocked['blocking_issues'], blocked

schema_text = schema_path.read_text(encoding='utf-8')
assert 'restore_summary_ready' in schema_text and 'maxItems' in schema_text
assert 'restore_summary_blocked' in schema_text and 'minItems' in schema_text
PY

grep -q '^decision=restore_summary_ready$' "$TMPDIR/summary-ready.report"
grep -q '^decision=restore_summary_blocked$' "$TMPDIR/summary-blocked.report"
grep -q '^blocking_issue_count=0$' "$TMPDIR/summary-ready.report"
grep -Eq '^blocking_issue_count=[1-9][0-9]*$' "$TMPDIR/summary-blocked.report"

echo "host_vm_policy_restore_release_summary schema example tests passed"
