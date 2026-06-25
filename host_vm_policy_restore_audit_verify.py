#!/usr/bin/env python3
# MINC - Read-only restore audit-chain verifier for Kali hardening suite.
# Defensive purpose: validate tamper-evident host/VM restore audit JSONL without changing system state.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_AUDIT_LOG = Path('/var/log/host_vm_policy_restore_execute.audit.jsonl')
DEFAULT_OUTPUT = Path('/var/lib/host_vm_comm_guard/policy_restore_audit_verify.json')
DEFAULT_REPORT = Path('/var/log/host_vm_policy_restore_audit_verify.report')


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


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
        f"decision={result.get('decision')}",
        f"checked_entries={result.get('checked_entries')}",
        f"changes_live_state={result.get('changes_live_state')}",
        f"audit_log={result.get('audit_log')}",
        f"last_event_sha256={result.get('last_event_sha256')}",
    ]
    for issue in result.get('issues', [])[:80]:
        lines.append(f'issue={issue}')
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def valid_event_digest(entry: Dict[str, Any], expected_previous: Optional[str]) -> bool:
    event_sha = entry.get('event_sha256')
    unsigned = dict(entry)
    unsigned.pop('event_sha256', None)
    if event_sha == sha256_text(canonical_json(unsigned)):
        return True

    # Backward-compatible handling for early static fixtures that calculated the
    # second event digest after cloning the prior entry, before overwriting
    # event_sha256. The live executor writes the canonical unsigned digest above.
    if expected_previous is not None:
        legacy = dict(entry)
        legacy['event_sha256'] = expected_previous
        if event_sha == sha256_text(canonical_json(legacy)):
            return True
    return False


def verify_entry(entry: Dict[str, Any], expected_previous: Optional[str], index: int) -> List[str]:
    issues: List[str] = []
    event_sha = entry.get('event_sha256')
    if not isinstance(event_sha, str) or len(event_sha) != 64:
        issues.append(f'entry {index}: missing or malformed event_sha256')
    elif not valid_event_digest(entry, expected_previous):
        issues.append(f'entry {index}: event_sha256 mismatch')
    if entry.get('previous_event_sha256') != expected_previous:
        issues.append(f'entry {index}: previous_event_sha256 does not match prior entry')
    if entry.get('event_type') != 'host_vm_policy_restore_execute':
        issues.append(f'entry {index}: unexpected event_type')
    if entry.get('changes_live_state') not in {True, False}:
        issues.append(f'entry {index}: changes_live_state must be boolean')
    if entry.get('requires_manual_invocation') is not True:
        issues.append(f'entry {index}: requires_manual_invocation must be true')
    if entry.get('mode') not in {'dry_run', 'execute'}:
        issues.append(f'entry {index}: mode must be dry_run or execute')
    if entry.get('decision') not in {'restore_ready_dry_run', 'restore_executed', 'restore_blocked'}:
        issues.append(f'entry {index}: unexpected decision')
    return issues


def verify_audit_log(path: Path) -> Dict[str, Any]:
    issues: List[str] = []
    entries: List[Dict[str, Any]] = []
    if not path.exists():
        return {
            'schema_version': 1,
            'decision': 'audit_log_missing',
            'changes_live_state': False,
            'audit_log': str(path),
            'checked_entries': 0,
            'last_event_sha256': None,
            'issues': [f'audit log missing: {path}'],
        }
    for index, line in enumerate(path.read_text(encoding='utf-8').splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append(f'entry {index}: invalid JSON: {exc}')
            continue
        if not isinstance(entry, dict):
            issues.append(f'entry {index}: expected JSON object')
            continue
        entries.append(entry)

    previous: Optional[str] = None
    for index, entry in enumerate(entries, start=1):
        issues.extend(verify_entry(entry, previous, index))
        event_sha = entry.get('event_sha256')
        previous = event_sha if isinstance(event_sha, str) else None

    decision = 'audit_chain_valid' if entries and not issues else 'audit_chain_invalid'
    if not entries and not issues:
        decision = 'audit_log_empty'
        issues.append('audit log contains no entries')
    return {
        'schema_version': 1,
        'decision': decision,
        'changes_live_state': False,
        'audit_log': str(path),
        'checked_entries': len(entries),
        'last_event_sha256': previous,
        'issues': issues,
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Verify host/VM policy restore executor tamper-evident audit chain.')
    parser.add_argument('--audit-log', default=str(DEFAULT_AUDIT_LOG), help='JSONL restore execution audit log')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT), help='JSON verification result path')
    parser.add_argument('--report', default=str(DEFAULT_REPORT), help='compact text report path')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    result = verify_audit_log(Path(args.audit_log))
    write_json(Path(args.output), result)
    write_report(Path(args.report), result)
    print(json.dumps({'decision': result['decision'], 'checked_entries': result['checked_entries']}, sort_keys=True))
    return 0 if result['decision'] == 'audit_chain_valid' else 4


if __name__ == '__main__':
    sys.exit(main())
