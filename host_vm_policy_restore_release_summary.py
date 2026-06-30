#!/usr/bin/env python3
# MINC - Passive release-readiness summary for host/VM policy restore executor evidence.
# Defensive purpose: summarize aggregate restore executor JSON without touching live host or VM state.

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

READY_DECISION = 'restore_ready_dry_run'
BLOCKED_DECISION = 'restore_blocked'
SUMMARY_READY = 'restore_summary_ready'
SUMMARY_BLOCKED = 'restore_summary_blocked'


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


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


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Dict[str, Any], mode: int = 0o640) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def write_report(path: Path, summary: Dict[str, Any]) -> None:
    ensure_parent(path)
    lines = [
        f"created_utc={summary.get('created_utc')}",
        f"decision={summary.get('decision')}",
        f"summary_ready={str(summary.get('summary_ready')).lower()}",
        f"ready_restore_decision={summary.get('ready_restore_decision')}",
        f"expected_blocked_decision={summary.get('expected_blocked_decision')}",
        f"blocking_issue_count={len(summary.get('blocking_issues', []))}",
        f"changes_live_state={str(summary.get('changes_live_state')).lower()}",
        f"aggregate_evidence_only={str(summary.get('aggregate_evidence_only')).lower()}",
    ]
    for issue in summary.get('blocking_issues', [])[:40]:
        lines.append(f'blocking_issue={issue}')
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def validate_ready_evidence(result: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    if result.get('decision') != READY_DECISION:
        issues.append(f'ready restore decision must be {READY_DECISION}')
    if result.get('mode') != 'dry_run':
        issues.append('ready restore evidence must come from dry_run mode')
    if result.get('changes_live_state') is not False:
        issues.append('ready restore evidence must not change live state')
    if result.get('requires_manual_invocation') is not True:
        issues.append('restore executor must require manual invocation')
    if result.get('safe_default') != 'dry-run unless --execute is passed and approval validation is fresh and valid':
        issues.append('restore executor safe_default is missing or unexpected')
    actions = result.get('actions')
    if not isinstance(actions, list) or not actions:
        issues.append('ready restore evidence must include at least one preflight action')
    else:
        if not any(isinstance(action, dict) and action.get('status') == 'preflight_ok' for action in actions):
            issues.append('ready restore evidence must include a preflight_ok action')
    if result.get('issues') not in ([], None):
        issues.append('ready restore evidence must not carry blocking issues')
    return issues


def validate_expected_blocked(result: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    if result.get('decision') != BLOCKED_DECISION:
        issues.append(f'expected-blocked restore decision must be {BLOCKED_DECISION}')
    if result.get('changes_live_state') is not False:
        issues.append('expected-blocked restore evidence must not change live state')
    result_issues = result.get('issues')
    if not isinstance(result_issues, list) or not result_issues:
        issues.append('expected-blocked restore evidence must include at least one issue')
    return issues


def build_summary(ready: Dict[str, Any], expected_blocked: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    blocking_issues = validate_ready_evidence(ready)
    expected_decision: Optional[str] = None
    if expected_blocked is not None:
        expected_decision = str(expected_blocked.get('decision'))
        blocking_issues.extend(validate_expected_blocked(expected_blocked))

    decision = SUMMARY_READY if not blocking_issues else SUMMARY_BLOCKED
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'decision': decision,
        'summary_ready': decision == SUMMARY_READY,
        'ready_restore_decision': ready.get('decision'),
        'expected_blocked_decision': expected_decision,
        'blocking_issues': blocking_issues,
        'changes_live_state': False,
        'reads_raw_telemetry': False,
        'aggregate_evidence_only': True,
        'requires_manual_invocation': True,
        'safe_default': 'passive summary only; restore execution remains manual and dry-run by default',
        'reviewer_handoff': {
            'confirm_ready_decision': READY_DECISION,
            'confirm_expected_blocked_decision': BLOCKED_DECISION if expected_blocked is not None else None,
            'confirm_no_live_state_change': True,
            'confirm_manual_restore_only': True,
        },
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Summarize passive restore executor readiness evidence for release review.')
    parser.add_argument('ready_restore_result', help='restore executor dry-run JSON with restore_ready_dry_run decision')
    parser.add_argument('--expected-blocked-result', help='optional restore_blocked JSON fixture used to prove fail-closed behavior')
    parser.add_argument('--output', required=True, help='summary JSON output path')
    parser.add_argument('--report', required=True, help='compact key=value report output path')
    parser.add_argument('--strict', action='store_true', help='exit non-zero unless the restore summary is ready')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    ready = load_json(Path(args.ready_restore_result))
    expected = load_json(Path(args.expected_blocked_result)) if args.expected_blocked_result else None
    summary = build_summary(ready, expected)
    write_json(Path(args.output), summary)
    write_report(Path(args.report), summary)
    print(json.dumps({'decision': summary.get('decision'), 'summary_ready': summary.get('summary_ready'), 'output': args.output}, sort_keys=True))
    if args.strict and not summary.get('summary_ready'):
        return 4
    return 0


if __name__ == '__main__':
    sys.exit(main())
