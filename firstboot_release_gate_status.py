#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate status reader.
# Purpose: read aggregate-only release-gate summary artifacts without changing host or VM state.

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional

DEFAULT_SUMMARY = Path('/var/log/firstboot_release_gate.summary.env')
REQUIRED_FIELDS = (
    'FIRSTBOOT_RELEASE_GATE_SCHEMA_VERSION',
    'FIRSTBOOT_RELEASE_GATE_COMPONENT',
    'FIRSTBOOT_RELEASE_GATE_CREATED_UTC',
    'FIRSTBOOT_RELEASE_GATE_OK',
    'FIRSTBOOT_RELEASE_GATE_DECISION',
    'FIRSTBOOT_RELEASE_GATE_STATUS',
    'FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT',
    'FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT',
    'FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT',
    'FIRSTBOOT_RELEASE_GATE_PRIVACY_SCOPE',
)
INTEGER_FIELDS = {
    'FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT',
    'FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT',
    'FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT',
}


def parse_summary_line(line: str) -> tuple[str, str]:
    key, separator, raw_value = line.partition('=')
    if not separator:
        raise ValueError(f'missing equals separator: {line!r}')
    key = key.strip()
    value = raw_value.strip()
    if not key or not key.replace('_', '').isalnum() or not key.isupper():
        raise ValueError(f'invalid field name: {key!r}')
    if len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        raise ValueError(f'{key} must use a double-quoted value')
    return key, unquote_env_value(value[1:-1])


def unquote_env_value(value: str) -> str:
    output: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            output.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        else:
            output.append(char)
    if escaped:
        output.append('\\')
    return ''.join(output)


def load_summary(path: Path) -> tuple[Dict[str, str], list[str]]:
    if not path.exists() or not path.is_file():
        return {}, [f'missing_summary:{path}']
    fields: Dict[str, str] = {}
    blockers: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        try:
            key, value = parse_summary_line(stripped)
        except ValueError as exc:
            blockers.append(f'invalid_summary_line:{line_number}:{exc}')
            continue
        if key in fields:
            blockers.append(f'duplicate_summary_field:{key}')
        fields[key] = value
    missing = [field for field in REQUIRED_FIELDS if field not in fields]
    blockers.extend(f'missing_summary_field:{field}' for field in missing)
    for field in INTEGER_FIELDS.intersection(fields):
        if not fields[field].isdigit():
            blockers.append(f'invalid_integer_field:{field}')
    if fields.get('FIRSTBOOT_RELEASE_GATE_PRIVACY_SCOPE') != 'aggregate_only':
        blockers.append('privacy_scope_not_aggregate_only')
    if fields.get('FIRSTBOOT_RELEASE_GATE_OK') not in {'true', 'false'}:
        blockers.append('invalid_ok_field')
    if fields.get('FIRSTBOOT_RELEASE_GATE_STATUS') not in {'pass', 'stop'}:
        blockers.append('invalid_status_field')
    return fields, blockers


def build_status(path: Path) -> Dict[str, object]:
    fields, blockers = load_summary(path)
    gate_ok = fields.get('FIRSTBOOT_RELEASE_GATE_OK') == 'true'
    release_gate = fields.get('FIRSTBOOT_RELEASE_GATE_STATUS', 'unknown')
    decision = fields.get('FIRSTBOOT_RELEASE_GATE_DECISION', 'unknown')
    artifact_count = int(fields.get('FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT', '0')) if fields.get('FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT', '').isdigit() else 0
    blocker_count = int(fields.get('FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT', '0')) if fields.get('FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT', '').isdigit() else 0
    stale_or_skewed_count = int(fields.get('FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT', '0')) if fields.get('FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT', '').isdigit() else 0
    ok = gate_ok and release_gate == 'pass' and not blockers
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_status',
        'summary_path': str(path),
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'source_decision': decision,
        'source_release_gate': release_gate,
        'source_created_utc': fields.get('FIRSTBOOT_RELEASE_GATE_CREATED_UTC', 'unknown'),
        'source_component': fields.get('FIRSTBOOT_RELEASE_GATE_COMPONENT', 'unknown'),
        'artifact_count': artifact_count,
        'blocker_count': blocker_count,
        'stale_or_skewed_count': stale_or_skewed_count,
        'validation_blockers': sorted(set(blockers)),
        'safe_default': 'read-only summary reader; no host, VM, firewall, service, model, dataset, approval, restore, or firstboot state was changed',
        'privacy_note': 'consumes only aggregate summary fields and does not source shell content, read raw logs, inspect packets, capture telemetry, credentials, hostnames, usernames, secrets, model binaries, or datasets',
        'operator_next_steps': operator_next_steps(blockers, release_gate, blocker_count, stale_or_skewed_count),
    }


def operator_next_steps(blockers: list[str], release_gate: str, blocker_count: int, stale_or_skewed_count: int) -> list[str]:
    if not blockers and release_gate == 'pass' and blocker_count == 0:
        return ['Proceed with release evidence review using the authoritative JSON and Markdown gate artifacts.']
    actions = []
    if blockers:
        actions.append('Regenerate the firstboot release-gate summary from the authoritative JSON/Markdown artifacts before relying on dashboard status.')
    if release_gate != 'pass' or blocker_count:
        actions.append('Review the authoritative firstboot release-gate JSON and Markdown artifacts for blocker details before promotion.')
    if stale_or_skewed_count:
        actions.append('Regenerate stale or clock-skewed firstboot release evidence before promotion.')
    return sorted(set(actions))


def render_text(status: Dict[str, object]) -> str:
    lines = [
        'Firstboot release-gate status',
        f"decision: {status['decision']}",
        f"release_gate: {status['release_gate']}",
        f"source_decision: {status['source_decision']}",
        f"source_release_gate: {status['source_release_gate']}",
        f"artifact_count: {status['artifact_count']}",
        f"blocker_count: {status['blocker_count']}",
        f"stale_or_skewed_count: {status['stale_or_skewed_count']}",
        'validation_blockers:',
    ]
    validation_blockers = status.get('validation_blockers') or []
    if validation_blockers:
        lines.extend(f'- {blocker}' for blocker in validation_blockers)
    else:
        lines.append('- none')
    lines.append('operator_next_steps:')
    lines.extend(f"- {step}" for step in status.get('operator_next_steps', []))
    return '\n'.join(lines) + '\n'


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Read a passive aggregate firstboot release-gate summary artifact.')
    parser.add_argument('--summary', default=str(DEFAULT_SUMMARY), help='Path to firstboot_release_gate.summary.env.')
    parser.add_argument('--format', choices=('json', 'text'), default='text')
    parser.add_argument('--require-pass', action='store_true', help='Exit non-zero unless the aggregate summary is valid and passing.')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    status = build_status(Path(args.summary))
    if args.format == 'json':
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        print(render_text(status), end='')
    return 0 if status['ok'] or not args.require_pass else 7


if __name__ == '__main__':
    sys.exit(main())
