#!/usr/bin/env bash
# MINC - Static tests for read-only host/VM restore audit-chain verifier.
# Defensive test only: validates tamper-evident JSONL detection without touching live audit logs.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_policy_restore_audit_verify.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"

if ! grep -q "changes_live_state': False" "$SCRIPT"; then
    echo "audit verifier must be read-only" >&2
    exit 1
fi
if grep -Eq "subprocess|systemctl|nft |shutil|os\.replace" "$SCRIPT"; then
    echo "audit verifier must not call system mutation helpers" >&2
    exit 1
fi

python3 - "$TMPDIR/audit.jsonl" <<'PY'
import hashlib
import json
import sys

path = sys.argv[1]

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

def digest(data):
    return hashlib.sha256(canonical(data).encode()).hexdigest()

first = {
    'schema_version': 1,
    'created_utc': '2026-06-25T00:00:00Z',
    'event_type': 'host_vm_policy_restore_execute',
    'previous_event_sha256': None,
    'previous_event_status': 'missing',
    'result_sha256': '0' * 64,
    'decision': 'restore_ready_dry_run',
    'mode': 'dry_run',
    'changes_live_state': False,
    'requires_manual_invocation': True,
    'output': '/tmp/result.json',
    'report': '/tmp/report',
    'plan': '/tmp/plan.json',
    'plan_sha256': '1' * 64,
    'approval_check': '/tmp/approval.json',
    'approval_check_sha256': '2' * 64,
    'max_approval_age_seconds': 900,
    'reload_after_restore': False,
    'issue_count': 0,
    'action_count': 1,
    'targets': ['/etc/host_vm_comm_guard.conf'],
}
first['event_sha256'] = digest(first)
second = dict(first)
second['created_utc'] = '2026-06-25T00:01:00Z'
second['decision'] = 'restore_blocked'
second['previous_event_sha256'] = first['event_sha256']
second['previous_event_status'] = 'ok'
second['issue_count'] = 1
second['event_sha256'] = digest(second)
with open(path, 'w', encoding='utf-8') as handle:
    handle.write(json.dumps(first, sort_keys=True) + '\n')
    handle.write(json.dumps(second, sort_keys=True) + '\n')
PY

python3 "$SCRIPT" \
    --audit-log "$TMPDIR/audit.jsonl" \
    --output "$TMPDIR/valid.json" \
    --report "$TMPDIR/valid.report" >/dev/null

python3 - "$TMPDIR/valid.json" "$TMPDIR/valid.report" <<'PY'
import json
import pathlib
import sys
result = json.load(open(sys.argv[1], encoding='utf-8'))
report = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert result['decision'] == 'audit_chain_valid', result
assert result['checked_entries'] == 2, result
assert result['changes_live_state'] is False, result
assert 'decision=audit_chain_valid' in report, report
PY

python3 - "$TMPDIR/audit.jsonl" "$TMPDIR/tampered.jsonl" <<'PY'
import json
import sys
source, target = sys.argv[1:]
lines = open(source, encoding='utf-8').read().splitlines()
entry = json.loads(lines[1])
entry['decision'] = 'restore_executed'
lines[1] = json.dumps(entry, sort_keys=True)
open(target, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
PY

if python3 "$SCRIPT" \
    --audit-log "$TMPDIR/tampered.jsonl" \
    --output "$TMPDIR/tampered.json" \
    --report "$TMPDIR/tampered.report" >/dev/null 2>&1; then
    echo "audit verifier must reject tampered audit entries" >&2
    exit 1
fi
python3 - "$TMPDIR/tampered.json" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1], encoding='utf-8'))
assert result['decision'] == 'audit_chain_invalid', result
assert any('event_sha256 mismatch' in issue for issue in result['issues']), result
PY

echo "host_vm_policy_restore_audit_verify static tests passed"
