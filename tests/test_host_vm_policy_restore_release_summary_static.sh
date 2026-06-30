#!/usr/bin/env bash
# MINC - Static and behavioral tests for passive restore release summary evidence.
# Defensive test only: validates aggregate JSON contracts without touching live policy.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_policy_restore_release_summary.py"
WORKFLOW="$ROOT_DIR/.github/workflows/restore-executor-release-gate.yml"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"

# The hosted release gate must publish the passive summary artifacts alongside executor evidence.
grep -q "host_vm_policy_restore_release_summary.py" "$WORKFLOW"
grep -q "restore-release-summary.json" "$WORKFLOW"
grep -q "restore-release-summary.report" "$WORKFLOW"
grep -q "restore-executor-release-evidence" "$WORKFLOW"
grep -q "expected-blocked-result" "$WORKFLOW"

# The summary CLI remains passive, aggregate-only, and strict by default for release gates.
grep -q "restore_summary_ready" "$SCRIPT"
grep -q "restore_summary_blocked" "$SCRIPT"
grep -q "restore_ready_dry_run" "$SCRIPT"
grep -q "restore_blocked" "$SCRIPT"
grep -q "aggregate_evidence_only.*True" "$SCRIPT"
grep -q "passive summary only" "$SCRIPT"

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$TMPDIR/ready.json" "$NOW" <<'PY'
import json, sys
path, now = sys.argv[1:]
json.dump({
    'schema_version': 1,
    'created_utc': now,
    'mode': 'dry_run',
    'decision': 'restore_ready_dry_run',
    'changes_live_state': False,
    'requires_manual_invocation': True,
    'issues': [],
    'safe_default': 'dry-run unless --execute is passed and approval validation is fresh and valid',
    'actions': [{'name': 'host_vm_comm_guard.conf', 'target': '/etc/host_vm_comm_guard.conf', 'status': 'preflight_ok'}],
}, open(path, 'w'))
PY

python3 - "$TMPDIR/blocked.json" "$NOW" <<'PY'
import json, sys
path, now = sys.argv[1:]
json.dump({
    'schema_version': 1,
    'created_utc': now,
    'mode': 'dry_run',
    'decision': 'restore_blocked',
    'changes_live_state': False,
    'requires_manual_invocation': True,
    'issues': ['approval check decision must be approval_valid'],
    'actions': [],
}, open(path, 'w'))
PY

python3 "$SCRIPT" "$TMPDIR/ready.json" \
    --expected-blocked-result "$TMPDIR/blocked.json" \
    --output "$TMPDIR/summary.json" \
    --report "$TMPDIR/summary.report" \
    --strict >/dev/null

python3 - "$TMPDIR/summary.json" <<'PY'
import json, sys
summary = json.load(open(sys.argv[1]))
assert summary['decision'] == 'restore_summary_ready', summary
assert summary['summary_ready'] is True, summary
assert summary['ready_restore_decision'] == 'restore_ready_dry_run', summary
assert summary['expected_blocked_decision'] == 'restore_blocked', summary
assert summary['blocking_issues'] == [], summary
assert summary['changes_live_state'] is False, summary
assert summary['reads_raw_telemetry'] is False, summary
assert summary['aggregate_evidence_only'] is True, summary
PY

grep -q '^decision=restore_summary_ready$' "$TMPDIR/summary.report"
grep -q '^blocking_issue_count=0$' "$TMPDIR/summary.report"

python3 - "$TMPDIR/ready.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data['changes_live_state'] = True
json.dump(data, open(path, 'w'))
PY

if python3 "$SCRIPT" "$TMPDIR/ready.json" \
    --expected-blocked-result "$TMPDIR/blocked.json" \
    --output "$TMPDIR/bad-summary.json" \
    --report "$TMPDIR/bad-summary.report" \
    --strict >/dev/null 2>&1; then
    echo "strict summary must fail when ready evidence changed live state" >&2
    exit 1
fi

python3 - "$TMPDIR/bad-summary.json" <<'PY'
import json, sys
summary = json.load(open(sys.argv[1]))
assert summary['decision'] == 'restore_summary_blocked', summary
assert summary['summary_ready'] is False, summary
assert any('must not change live state' in issue for issue in summary['blocking_issues']), summary
PY

echo "host_vm_policy_restore_release_summary static tests passed"
