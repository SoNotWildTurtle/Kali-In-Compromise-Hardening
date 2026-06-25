#!/usr/bin/env bash
# MINC - Integration-style fixture tests for the manual host/VM restore executor.
# Defensive test only: exercises review-gated dry-run, execute logic, and refusal paths without mutating /etc.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_policy_restore_execute.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"

mkdir -p "$TMPDIR/known_good" "$TMPDIR/out" "$TMPDIR/log"
printf 'HOST_VM_MODE=isolated\nHOST_VM_POLICY_VERSION=fixture\n' > "$TMPDIR/known_good/host_vm_comm_guard.conf"
printf 'table inet host_vm_comm_guard { chain input { type filter hook input priority 0; policy drop; } }\n' > "$TMPDIR/known_good/host_vm_comm_guard.nft"
CONF_SHA="$(sha256sum "$TMPDIR/known_good/host_vm_comm_guard.conf" | awk '{print $1}')"
NFT_SHA="$(sha256sum "$TMPDIR/known_good/host_vm_comm_guard.nft" | awk '{print $1}')"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - "$TMPDIR/plan.json" "$TMPDIR/known_good/host_vm_comm_guard.conf" "$TMPDIR/known_good/host_vm_comm_guard.nft" "$CONF_SHA" "$NFT_SHA" "$NOW" <<'PY'
import json
import sys
plan, conf_source, nft_source, conf_sha, nft_sha, now = sys.argv[1:]
json.dump({
    'decision': 'manual_restore_review_required',
    'created_utc': now,
    'actions': [
        {
            'name': 'host_vm_comm_guard.conf',
            'source': conf_source,
            'target': '/etc/host_vm_comm_guard.conf',
            'status': 'manual_restore_candidate',
            'known_good': {'sha256': conf_sha},
        },
        {
            'name': 'host_vm_comm_guard.nft',
            'source': nft_source,
            'target': '/etc/nftables.d/host_vm_comm_guard.nft',
            'status': 'manual_restore_candidate',
            'known_good': {'sha256': nft_sha},
        },
    ],
}, open(plan, 'w', encoding='utf-8'))
PY

python3 - "$TMPDIR/approval.json" "$NOW" <<'PY'
import json
import sys
path, now = sys.argv[1:]
json.dump({
    'decision': 'approval_valid',
    'created_utc': now,
    'plan_decision': 'manual_restore_review_required',
    'changes_live_state': False,
}, open(path, 'w', encoding='utf-8'))
PY

# Realistic dry-run: allowed /etc targets, valid candidate files, valid fresh approval.
# Omit --execute so this remains non-mutating even when run as root in CI or a VM.
python3 "$SCRIPT" \
    --plan "$TMPDIR/plan.json" \
    --approval-check "$TMPDIR/approval.json" \
    --output "$TMPDIR/out/dry_run.json" \
    --report "$TMPDIR/log/dry_run.report" >/dev/null

python3 - "$TMPDIR/out/dry_run.json" "$TMPDIR/log/dry_run.report" <<'PY'
import json
import pathlib
import sys
result = json.load(open(sys.argv[1], encoding='utf-8'))
report = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert result['decision'] == 'restore_ready_dry_run', result
assert result['mode'] == 'dry_run', result
assert result['changes_live_state'] is False, result
assert result['requires_manual_invocation'] is True, result
assert len(result['actions']) == 2, result
assert all(action['status'] == 'preflight_ok' for action in result['actions']), result
assert 'decision=restore_ready_dry_run' in report, report
assert 'changes_live_state=False' in report, report
PY

# Safe execute-mode harness: exercise the executor's approved restore branch while
# monkeypatching copy/reload functions into a temporary shadow root. This proves the
# execute path and backup metadata without writing to live /etc or invoking systemctl/nft.
python3 - "$SCRIPT" "$TMPDIR/plan.json" "$TMPDIR/approval.json" "$TMPDIR/shadow_root" "$TMPDIR/backups" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import shutil
import sys
from types import SimpleNamespace

script, plan_path, approval_path, shadow_root, backup_dir = sys.argv[1:]
spec = importlib.util.spec_from_file_location('restore_execute_under_test', script)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

shadow = pathlib.Path(shadow_root)
shadow.mkdir(parents=True, exist_ok=True)
copied_targets = []

def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        digest.update(handle.read())
    return digest.hexdigest()

def shadow_copy_with_backup(source, target, requested_backup_dir):
    assert str(target).startswith('/etc/'), target
    assert pathlib.Path(str(requested_backup_dir)) == pathlib.Path(backup_dir)
    shadow_target = shadow / str(target).lstrip('/')
    shadow_target.parent.mkdir(parents=True, exist_ok=True)
    if shadow_target.exists():
        pathlib.Path(backup_dir).mkdir(parents=True, exist_ok=True)
        backup_path = pathlib.Path(backup_dir) / f'{target.name}.shadow.bak'
        shutil.copy2(shadow_target, backup_path)
    else:
        backup_path = None
    shutil.copy2(source, shadow_target)
    copied_targets.append(str(target))
    return {
        'backup': str(backup_path) if backup_path else None,
        'target_after_sha256': sha256_file(shadow_target),
        'shadow_target': str(shadow_target),
    }

def shadow_run_reload(target, allow_reload):
    assert allow_reload is False
    return {'status': 'skipped', 'detail': 'shadow harness blocks live reloads'}

module.copy_with_backup = shadow_copy_with_backup
module.run_reload = shadow_run_reload

plan = module.load_json(pathlib.Path(plan_path))
approval = module.load_json(pathlib.Path(approval_path))
args = SimpleNamespace(
    execute=True,
    backup_dir=backup_dir,
    reload_after_restore=False,
    max_approval_age_seconds=15 * 60,
)
result = module.execute(plan, approval, args)
assert result['decision'] == 'restore_executed', result
assert result['mode'] == 'execute', result
assert result['changes_live_state'] is True, result
assert copied_targets == ['/etc/host_vm_comm_guard.conf', '/etc/nftables.d/host_vm_comm_guard.nft'], result
restored = [action for action in result['actions'] if action.get('status') == 'restored']
assert len(restored) == 2, result
assert all(action['reload']['status'] == 'skipped' for action in restored), result
for action in restored:
    assert action['target_after_sha256'] == action['source_sha256'] if 'source_sha256' in action else True
    assert pathlib.Path(action['shadow_target']).exists(), action
print(json.dumps({'decision': result['decision'], 'restored': copied_targets}, sort_keys=True))
PY

# Refusal: an otherwise valid dry-run must block when the known-good source hash no longer
# matches the reviewed plan manifest.
printf 'tampered-after-plan\n' >> "$TMPDIR/known_good/host_vm_comm_guard.conf"
if python3 "$SCRIPT" \
    --plan "$TMPDIR/plan.json" \
    --approval-check "$TMPDIR/approval.json" \
    --output "$TMPDIR/out/hash_mismatch.json" \
    --report "$TMPDIR/log/hash_mismatch.report" >/dev/null 2>&1; then
    echo "executor must reject known-good source hash mismatch" >&2
    exit 1
fi
python3 - "$TMPDIR/out/hash_mismatch.json" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1], encoding='utf-8'))
assert result['decision'] == 'restore_blocked', result
assert result['changes_live_state'] is False, result
assert any('sha256 mismatch' in issue for issue in result['issues']), result
PY

# Refusal: approval validation must be fresh, not replayed from an old restore window.
python3 - "$TMPDIR/approval.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.load(open(path, encoding='utf-8'))
data['created_utc'] = '2000-01-01T00:00:00Z'
json.dump(data, open(path, 'w', encoding='utf-8'))
PY
if python3 "$SCRIPT" \
    --plan "$TMPDIR/plan.json" \
    --approval-check "$TMPDIR/approval.json" \
    --output "$TMPDIR/out/stale_approval.json" \
    --report "$TMPDIR/log/stale_approval.report" >/dev/null 2>&1; then
    echo "executor must reject stale approval validation" >&2
    exit 1
fi
python3 - "$TMPDIR/out/stale_approval.json" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1], encoding='utf-8'))
assert result['decision'] == 'restore_blocked', result
assert result['changes_live_state'] is False, result
assert any('approval check is stale' in issue for issue in result['issues']), result
PY

echo "host_vm_policy_restore_execute integration fixture tests passed"
