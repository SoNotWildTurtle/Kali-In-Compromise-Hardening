#!/usr/bin/env bash
# MINC - Static tests for approval-gated host/VM policy restore executor.
# Defensive test only: validates dry-run safety and refusal paths without touching live policy.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_policy_restore_execute.py"
SERVICE="$ROOT_DIR/host_vm_policy_restore_execute.service"
DOC="$ROOT_DIR/docs/host_vm_policy_restore_execute.md"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"

if ! grep -q "action='store_true'.*execute" "$SCRIPT"; then
    echo "executor must require explicit --execute" >&2
    exit 1
fi
if ! grep -q "restore_ready_dry_run" "$SCRIPT"; then
    echo "executor must expose a dry-run ready decision" >&2
    exit 1
fi
if ! grep -q "approval_valid" "$SCRIPT"; then
    echo "executor must depend on approval_valid" >&2
    exit 1
fi
if ! grep -q "manual_restore_review_required" "$SCRIPT"; then
    echo "executor must depend on restore plan review decision" >&2
    exit 1
fi
if ! grep -q "NoNewPrivileges=true" "$SERVICE" || ! grep -q "ProtectSystem=strict" "$SERVICE"; then
    echo "service must be sandboxed" >&2
    exit 1
fi
if ! grep -q "deliberately does not run from a timer" "$DOC"; then
    echo "documentation must state no timer/default automation" >&2
    exit 1
fi

mkdir -p "$TMPDIR/kg" "$TMPDIR/out" "$TMPDIR/log"
printf 'known-good-conf\n' > "$TMPDIR/kg/host_vm_comm_guard.conf"
KG_SHA="$(sha256sum "$TMPDIR/kg/host_vm_comm_guard.conf" | awk '{print $1}')"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$TMPDIR/plan.json" "$TMPDIR/kg/host_vm_comm_guard.conf" "$KG_SHA" "$NOW" <<'PY'
import json, sys
plan, source, sha, now = sys.argv[1:]
json.dump({
    'decision': 'manual_restore_review_required',
    'created_utc': now,
    'actions': [{
        'name': 'host_vm_comm_guard.conf',
        'source': source,
        'target': '/etc/host_vm_comm_guard.conf',
        'status': 'manual_restore_candidate',
        'known_good': {'sha256': sha},
    }],
}, open(plan, 'w'))
PY
python3 - "$TMPDIR/approval.json" "$NOW" <<'PY'
import json, sys
path, now = sys.argv[1:]
json.dump({
    'decision': 'approval_valid',
    'created_utc': now,
    'plan_decision': 'manual_restore_review_required',
    'changes_live_state': False,
}, open(path, 'w'))
PY

python3 "$SCRIPT" \
    --plan "$TMPDIR/plan.json" \
    --approval-check "$TMPDIR/approval.json" \
    --output "$TMPDIR/out/result.json" \
    --report "$TMPDIR/log/report" >/dev/null

python3 - "$TMPDIR/out/result.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
assert result['decision'] == 'restore_ready_dry_run', result
assert result['changes_live_state'] is False, result
actions = result['actions']
assert actions and actions[0]['target'] == '/etc/host_vm_comm_guard.conf', actions
assert actions[0]['status'] == 'preflight_ok', actions
PY

python3 - "$TMPDIR/approval.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data['decision'] = 'approval_rejected'
json.dump(data, open(path, 'w'))
PY
if python3 "$SCRIPT" \
    --plan "$TMPDIR/plan.json" \
    --approval-check "$TMPDIR/approval.json" \
    --output "$TMPDIR/out/rejected.json" \
    --report "$TMPDIR/log/rejected" >/dev/null 2>&1; then
    echo "executor must fail when approval is rejected" >&2
    exit 1
fi

python3 - "$TMPDIR/out/rejected.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
assert result['decision'] == 'restore_blocked', result
assert result['changes_live_state'] is False, result
PY

echo "host_vm_policy_restore_execute static tests passed"
