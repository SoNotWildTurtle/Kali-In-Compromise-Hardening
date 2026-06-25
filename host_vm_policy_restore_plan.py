#!/usr/bin/env python3
# MINC - Review-only host/VM policy restore planner for Kali hardening suite.
# Purpose: prepare a reversible recovery plan from known-good policy files without changing live state.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

STATE_DIR = Path('/var/lib/host_vm_comm_guard')
KNOWN_GOOD_DIR = STATE_DIR / 'known_good'
DEFAULT_VERIFY = STATE_DIR / 'policy_verify.json'
DEFAULT_BASELINE = STATE_DIR / 'policy_attestation.baseline.json'
DEFAULT_PLAN = STATE_DIR / 'policy_restore_plan.json'
DEFAULT_REPORT = Path('/var/log/host_vm_policy_restore_plan.report')
DEFAULT_CONF = Path('/etc/host_vm_comm_guard.conf')
DEFAULT_NFT = Path('/etc/nftables.d/host_vm_comm_guard.nft')

RESTORABLE_FILES = {
    'host_vm_comm_guard.conf': DEFAULT_CONF,
    'host_vm_comm_guard.nft': DEFAULT_NFT,
}


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


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


def load_json(path: Path, required: bool = True) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        if required:
            raise SystemExit(f'missing required JSON file: {path}')
        return {}
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


def file_snapshot(path: Path) -> Dict[str, Any]:
    return {
        'path': str(path),
        'exists': path.exists(),
        'sha256': sha256_file(path),
        'mode': oct(path.stat().st_mode & 0o777) if path.exists() else None,
    }


def baseline_digest(baseline_path: Path) -> Optional[str]:
    return sha256_file(baseline_path)


def write_report(report_path: Path, result: Dict[str, Any]) -> None:
    ensure_parent(report_path)
    lines = [
        f"created_utc={result.get('created_utc')}",
        f"decision={result.get('decision')}",
        f"verify_decision={result.get('verify_decision')}",
        f"known_good_dir={result.get('known_good_dir')}",
        f"changes_live_state={result.get('changes_live_state')}",
    ]
    for action in result.get('actions', [])[:20]:
        lines.append(f"action={action.get('status')}|{action.get('target')}|{action.get('detail')}")
    report_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(report_path, 0o640)
    except OSError:
        pass


def capture_known_good(known_good_dir: Path, baseline_path: Path, force: bool = False) -> Dict[str, Any]:
    known_good_dir.mkdir(parents=True, exist_ok=True)
    actions: List[Dict[str, Any]] = []
    for name, source in RESTORABLE_FILES.items():
        dest = known_good_dir / name
        if dest.exists() and not force:
            actions.append({'source': str(source), 'backup': str(dest), 'status': 'kept', 'detail': 'known-good copy already exists'})
            continue
        if not source.exists():
            actions.append({'source': str(source), 'backup': str(dest), 'status': 'missing_source', 'detail': 'source missing; nothing captured'})
            continue
        shutil.copy2(source, dest)
        try:
            os.chmod(dest, 0o640)
        except OSError:
            pass
        actions.append({'source': str(source), 'backup': str(dest), 'status': 'captured', 'sha256': sha256_file(dest)})
    manifest = {
        'schema_version': 1,
        'created_utc': utc_now(),
        'purpose': 'known-good source for reviewed host/VM communication policy recovery planning',
        'baseline': str(baseline_path),
        'baseline_sha256': baseline_digest(baseline_path),
        'files': {name: file_snapshot(known_good_dir / name) for name in RESTORABLE_FILES},
        'changes_live_state': False,
    }
    write_json(known_good_dir / 'manifest.json', manifest)
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'mode': 'capture_known_good',
        'decision': 'captured' if any(a['status'] == 'captured' for a in actions) else 'unchanged',
        'known_good_dir': str(known_good_dir),
        'changes_live_state': False,
        'actions': actions,
    }


def approval_hint(baseline_path: Path, verify: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'approved': False,
        'purpose': 'host_vm_policy_restore',
        'baseline_sha256': baseline_digest(baseline_path),
        'verify_created_utc': verify.get('created_utc'),
        'expires_utc': 'YYYY-MM-DDTHH:MM:SSZ',
        'reviewer': 'manual-review-required',
        'note': 'Set approved=true only after reviewing the restore plan and local console access/recovery path.',
    }


def plan_restore(verify: Dict[str, Any], known_good_dir: Path, baseline_path: Path) -> Dict[str, Any]:
    verify_decision = str(verify.get('decision', 'missing'))
    actions: List[Dict[str, Any]] = []
    missing = 0
    changed = 0
    for name, target in RESTORABLE_FILES.items():
        source = known_good_dir / name
        source_snapshot = file_snapshot(source)
        target_snapshot = file_snapshot(target)
        if not source.exists():
            status = 'missing_known_good'
            missing += 1
            detail = 'capture known-good files before relying on restore planning'
        elif source_snapshot.get('sha256') == target_snapshot.get('sha256'):
            status = 'already_matches_known_good'
            detail = 'target already matches known-good copy'
        else:
            status = 'manual_restore_candidate'
            changed += 1
            detail = 'review candidate; restore manually only with console access and explicit approval'
        actions.append({
            'name': name,
            'source': str(source),
            'target': str(target),
            'known_good': source_snapshot,
            'current': target_snapshot,
            'status': status,
            'detail': detail,
        })
    if verify_decision != 'restore_review':
        decision = 'no_restore_needed'
    elif missing:
        decision = 'restore_blocked_missing_known_good'
    elif changed:
        decision = 'manual_restore_review_required'
    else:
        decision = 'already_restored'
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'mode': 'plan_only',
        'decision': decision,
        'verify_decision': verify_decision,
        'known_good_dir': str(known_good_dir),
        'baseline': str(baseline_path),
        'baseline_sha256': baseline_digest(baseline_path),
        'approval_template': approval_hint(baseline_path, verify),
        'actions': actions,
        'changes_live_state': False,
        'safe_default': 'review-only; no firewall, systemd, model, or host state was changed',
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a review-only host/VM policy restore plan.')
    parser.add_argument('--verify', default=str(DEFAULT_VERIFY), help='policy verification JSON path')
    parser.add_argument('--baseline', default=str(DEFAULT_BASELINE), help='known-good attestation baseline JSON path')
    parser.add_argument('--known-good-dir', default=str(KNOWN_GOOD_DIR), help='known-good policy file directory')
    parser.add_argument('--output', default=str(DEFAULT_PLAN), help='restore plan/result JSON path')
    parser.add_argument('--report', default=str(DEFAULT_REPORT), help='compact restore report path')
    parser.add_argument('--capture-known-good', action='store_true', help='copy current policy files into known-good storage')
    parser.add_argument('--force-capture', action='store_true', help='replace existing known-good files during capture')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    verify_path = Path(args.verify)
    baseline_path = Path(args.baseline)
    known_good_dir = Path(args.known_good_dir)
    output_path = Path(args.output)
    report_path = Path(args.report)

    if args.capture_known_good:
        result = capture_known_good(known_good_dir, baseline_path, force=args.force_capture)
    else:
        verify = load_json(verify_path, required=True)
        result = plan_restore(verify, known_good_dir, baseline_path)

    write_json(output_path, result)
    write_report(report_path, result)
    print(json.dumps({'decision': result.get('decision'), 'mode': result.get('mode'), 'output': str(output_path)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
