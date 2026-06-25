#!/usr/bin/env python3
# MINC - Manual host/VM policy restore executor for Kali hardening suite.
# Purpose: restore only reviewed known-good host/VM policy files after fresh approval validation.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

STATE_DIR = Path('/var/lib/host_vm_comm_guard')
DEFAULT_PLAN = STATE_DIR / 'policy_restore_plan.json'
DEFAULT_APPROVAL_CHECK = STATE_DIR / 'policy_restore_approval_check.json'
DEFAULT_OUTPUT = STATE_DIR / 'policy_restore_execute.json'
DEFAULT_REPORT = Path('/var/log/host_vm_policy_restore_execute.report')
DEFAULT_BACKUP_DIR = STATE_DIR / 'pre_restore_backups'
DEFAULT_MAX_APPROVAL_AGE_SECONDS = 15 * 60

RESTORABLE_NAMES = {'host_vm_comm_guard.conf', 'host_vm_comm_guard.nft'}
RELOAD_TARGETS = {
    '/etc/host_vm_comm_guard.conf': ['systemctl', 'restart', 'host_vm_comm_guard.service'],
    '/etc/nftables.d/host_vm_comm_guard.nft': ['nft', '-c', '-f', '/etc/nftables.d/host_vm_comm_guard.nft'],
}


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def parse_utc(value: Any) -> Optional[int]:
    if not isinstance(value, str):
        return None
    try:
        return int(time.mktime(time.strptime(value, '%Y-%m-%dT%H:%M:%SZ')))
    except (TypeError, ValueError, OverflowError):
        return None


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise SystemExit(f'missing required JSON file: {path}') from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f'could not parse JSON file {path}: {exc}') from exc
    if not isinstance(data, dict):
        raise SystemExit(f'expected JSON object in {path}')
    return data


def write_json(path: Path, data: Dict[str, Any], mode: int = 0o640) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def write_report(path: Path, result: Dict[str, Any]) -> None:
    ensure_parent(path)
    lines = [
        f"created_utc={result.get('created_utc')}",
        f"mode={result.get('mode')}",
        f"decision={result.get('decision')}",
        f"changes_live_state={result.get('changes_live_state')}",
    ]
    for issue in result.get('issues', [])[:40]:
        lines.append(f'issue={issue}')
    for action in result.get('actions', [])[:40]:
        lines.append(f"action={action.get('status')}|{action.get('target')}|{action.get('detail')}")
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def validate_gate(plan: Dict[str, Any], approval_check: Dict[str, Any], max_age_seconds: int) -> List[str]:
    issues: List[str] = []
    if plan.get('decision') != 'manual_restore_review_required':
        issues.append('restore plan decision must be manual_restore_review_required')
    if approval_check.get('decision') != 'approval_valid':
        issues.append('approval check decision must be approval_valid')
    if approval_check.get('changes_live_state') is not False:
        issues.append('approval check must be validation-only')
    if approval_check.get('plan_decision') != plan.get('decision'):
        issues.append('approval check plan_decision does not match restore plan decision')
    created_epoch = parse_utc(approval_check.get('created_utc'))
    if created_epoch is None:
        issues.append('approval check created_utc is missing or invalid')
    else:
        age = int(time.time()) - created_epoch
        if age < -300:
            issues.append('approval check timestamp is in the future')
        elif age > max_age_seconds:
            issues.append(f'approval check is stale: age_seconds={age}, max_age_seconds={max_age_seconds}')
    return issues


def candidate_actions(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    for action in plan.get('actions', []):
        if not isinstance(action, dict):
            continue
        name = str(action.get('name', ''))
        status = action.get('status')
        source = Path(str(action.get('source', '')))
        target = Path(str(action.get('target', '')))
        if status != 'manual_restore_candidate':
            continue
        if name not in RESTORABLE_NAMES:
            continue
        actions.append({'name': name, 'source': source, 'target': target, 'raw': action})
    return actions


def preflight_action(action: Dict[str, Any]) -> Dict[str, Any]:
    source: Path = action['source']
    target: Path = action['target']
    raw = action['raw']
    issues: List[str] = []
    if not source.exists() or not source.is_file():
        issues.append(f'known-good source missing: {source}')
    if not str(target).startswith('/etc/'):
        issues.append(f'target must stay under /etc: {target}')
    expected_sha = raw.get('known_good', {}).get('sha256') if isinstance(raw.get('known_good'), dict) else None
    actual_sha = sha256_file(source)
    if expected_sha and actual_sha != expected_sha:
        issues.append(f'known-good source sha256 mismatch for {source}')
    return {
        'name': action['name'],
        'source': str(source),
        'target': str(target),
        'source_sha256': actual_sha,
        'target_before_sha256': sha256_file(target),
        'status': 'preflight_failed' if issues else 'preflight_ok',
        'issues': issues,
    }


def copy_with_backup(source: Path, target: Path, backup_dir: Path) -> Dict[str, Any]:
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f'{target.name}.{int(time.time())}.bak'
    if target.exists():
        shutil.copy2(target, backup_path)
        try:
            os.chmod(backup_path, 0o600)
        except OSError:
            pass
    ensure_parent(target)
    tmp_target = target.with_suffix(target.suffix + '.restore_tmp')
    shutil.copy2(source, tmp_target)
    os.replace(tmp_target, target)
    try:
        os.chmod(target, 0o640)
    except OSError:
        pass
    return {
        'backup': str(backup_path) if backup_path.exists() else None,
        'target_after_sha256': sha256_file(target),
    }


def run_reload(target: Path, allow_reload: bool) -> Dict[str, Any]:
    command = RELOAD_TARGETS.get(str(target))
    if not command:
        return {'status': 'not_needed', 'detail': 'no reload command registered for target'}
    if not allow_reload:
        return {'status': 'skipped', 'detail': 'reload requires --reload-after-restore'}
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
        return {
            'status': 'ok' if completed.returncode == 0 else 'failed',
            'command': command,
            'returncode': completed.returncode,
            'stdout_tail': completed.stdout[-1000:],
            'stderr_tail': completed.stderr[-1000:],
        }
    except Exception as exc:  # pragma: no cover - defensive OS boundary
        return {'status': 'failed', 'command': command, 'detail': str(exc)}


def execute(plan: Dict[str, Any], approval_check: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    issues = validate_gate(plan, approval_check, args.max_approval_age_seconds)
    actions: List[Dict[str, Any]] = []
    candidates = candidate_actions(plan)
    if not candidates:
        issues.append('restore plan contains no eligible manual_restore_candidate actions')

    preflight = [preflight_action(action) for action in candidates]
    actions.extend(preflight)
    for item in preflight:
        issues.extend(item.get('issues', []))

    mode = 'execute' if args.execute else 'dry_run'
    if issues:
        decision = 'restore_blocked'
    elif not args.execute:
        decision = 'restore_ready_dry_run'
    else:
        decision = 'restore_executed'
        for action in candidates:
            source: Path = action['source']
            target: Path = action['target']
            copy_result = copy_with_backup(source, target, Path(args.backup_dir))
            reload_result = run_reload(target, args.reload_after_restore)
            actions.append({
                'name': action['name'],
                'source': str(source),
                'target': str(target),
                'status': 'restored',
                'detail': 'copied known-good file to target after fresh approval validation',
                **copy_result,
                'reload': reload_result,
            })

    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'mode': mode,
        'decision': decision,
        'changes_live_state': bool(args.execute and not issues),
        'requires_manual_invocation': True,
        'approval_check_created_utc': approval_check.get('created_utc'),
        'max_approval_age_seconds': args.max_approval_age_seconds,
        'issues': issues,
        'actions': actions,
        'safe_default': 'dry-run unless --execute is passed and approval validation is fresh and valid',
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Manually restore reviewed known-good host/VM policy files after fresh approval validation.')
    parser.add_argument('--plan', default=str(DEFAULT_PLAN), help='restore plan JSON path')
    parser.add_argument('--approval-check', default=str(DEFAULT_APPROVAL_CHECK), help='approval validation JSON path')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT), help='executor result JSON path')
    parser.add_argument('--report', default=str(DEFAULT_REPORT), help='compact report path')
    parser.add_argument('--backup-dir', default=str(DEFAULT_BACKUP_DIR), help='where to save pre-restore backups')
    parser.add_argument('--max-approval-age-seconds', type=int, default=DEFAULT_MAX_APPROVAL_AGE_SECONDS, help='freshness window for approval validation')
    parser.add_argument('--execute', action='store_true', help='perform the restore; omitted means dry-run only')
    parser.add_argument('--reload-after-restore', action='store_true', help='validate/reload affected policy after restore')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.max_approval_age_seconds < 60 or args.max_approval_age_seconds > 24 * 60 * 60:
        raise SystemExit('--max-approval-age-seconds must be between 60 and 86400')
    plan = load_json(Path(args.plan))
    approval_check = load_json(Path(args.approval_check))
    result = execute(plan, approval_check, args)
    write_json(Path(args.output), result)
    write_report(Path(args.report), result)
    print(json.dumps({'decision': result.get('decision'), 'mode': result.get('mode'), 'output': args.output}, sort_keys=True))
    return 0 if result.get('decision') in {'restore_ready_dry_run', 'restore_executed'} else 4


if __name__ == '__main__':
    sys.exit(main())
