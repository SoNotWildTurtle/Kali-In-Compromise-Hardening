#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate handoff summary smoke checker.
# Purpose: parse aggregate-only .summary.env handoff freshness evidence for safe release gates.

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

DEFAULT_INPUT = Path('/var/log/firstboot_release_gate.handoff_freshness.summary.env')
DEFAULT_OUTPUT = Path('/var/log/firstboot_release_gate.handoff_summary_smoke.json')
REQUIRED_KEYS = (
    'FIRSTBOOT_HANDOFF_FRESHNESS_COMPONENT',
    'FIRSTBOOT_HANDOFF_FRESHNESS_CREATED_UTC',
    'FIRSTBOOT_HANDOFF_FRESHNESS_OK',
    'FIRSTBOOT_HANDOFF_FRESHNESS_DECISION',
    'FIRSTBOOT_HANDOFF_FRESHNESS_RELEASE_GATE',
    'FIRSTBOOT_HANDOFF_FRESHNESS_INPUT',
    'FIRSTBOOT_HANDOFF_FRESHNESS_MAX_AGE_MINUTES',
    'FIRSTBOOT_HANDOFF_FRESHNESS_TOTAL_ARTIFACTS',
    'FIRSTBOOT_HANDOFF_FRESHNESS_REQUIRED_VERIFIED',
    'FIRSTBOOT_HANDOFF_FRESHNESS_FRESH_REQUIRED_VERIFIED',
    'FIRSTBOOT_HANDOFF_FRESHNESS_VERIFICATION_EXISTS',
    'FIRSTBOOT_HANDOFF_FRESHNESS_VERIFICATION_FRESH',
    'FIRSTBOOT_HANDOFF_FRESHNESS_BLOCKER_COUNT',
    'FIRSTBOOT_HANDOFF_FRESHNESS_BLOCKERS',
    'FIRSTBOOT_HANDOFF_FRESHNESS_PRIVACY_SCOPE',
)
EXPECTED_COMPONENT = 'firstboot_release_gate_handoff_freshness'
EXPECTED_PRIVACY_SCOPE = 'aggregate_release_gate_handoff_freshness_only'
KEY_RE = re.compile(r'^[A-Z0-9_]+$')
TIMESTAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
PRIVACY_EXCLUDED = (
    'raw telemetry',
    'raw logs',
    'packets',
    'captures',
    'credentials',
    'hostnames',
    'usernames',
    'secrets',
    'model binaries',
    'datasets',
    'environment identifiers',
)


def utc_now(epoch: Optional[float] = None) -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() if epoch is None else epoch))


def unquote_env_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("'\\''", "'")
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_summary_env(path: Path) -> tuple[Dict[str, str], list[str]]:
    values: Dict[str, str] = {}
    blockers: list[str] = []
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except FileNotFoundError:
        return {}, [f'missing_summary:{path}']
    except UnicodeDecodeError as exc:
        return {}, [f'invalid_summary_encoding:{exc.reason}']

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            blockers.append(f'invalid_summary_line:{line_no}:missing_equals')
            continue
        key, raw_value = line.split('=', 1)
        key = key.strip()
        if not KEY_RE.match(key):
            blockers.append(f'invalid_summary_key:{line_no}:{key or "empty"}')
            continue
        values[key] = unquote_env_value(raw_value)
    return values, blockers


def as_int(values: Dict[str, str], key: str, blockers: list[str], minimum: int = 0) -> int:
    raw = values.get(key, '')
    try:
        value = int(raw)
    except ValueError:
        blockers.append(f'invalid_integer:{key}')
        return 0
    if value < minimum:
        blockers.append(f'invalid_integer_range:{key}')
    return value


def add_missing_required(values: Dict[str, str], blockers: list[str]) -> None:
    for key in REQUIRED_KEYS:
        if key not in values:
            blockers.append(f'missing_required_key:{key}')


def validate_summary(values: Dict[str, str], blockers: Iterable[str]) -> Dict[str, Any]:
    issues = list(blockers)
    add_missing_required(values, issues)

    component = values.get('FIRSTBOOT_HANDOFF_FRESHNESS_COMPONENT')
    privacy_scope = values.get('FIRSTBOOT_HANDOFF_FRESHNESS_PRIVACY_SCOPE')
    created = values.get('FIRSTBOOT_HANDOFF_FRESHNESS_CREATED_UTC', '')
    ok = values.get('FIRSTBOOT_HANDOFF_FRESHNESS_OK')
    decision = values.get('FIRSTBOOT_HANDOFF_FRESHNESS_DECISION')
    release_gate = values.get('FIRSTBOOT_HANDOFF_FRESHNESS_RELEASE_GATE')
    blockers_text = values.get('FIRSTBOOT_HANDOFF_FRESHNESS_BLOCKERS', '')

    if component and component != EXPECTED_COMPONENT:
        issues.append(f'component_mismatch:{component}')
    if privacy_scope and privacy_scope != EXPECTED_PRIVACY_SCOPE:
        issues.append(f'privacy_scope_mismatch:{privacy_scope}')
    if created and not TIMESTAMP_RE.match(created):
        issues.append('invalid_created_utc')
    if ok not in (None, '0', '1'):
        issues.append('invalid_ok_value')
    if decision and decision not in ('approved', 'deferred'):
        issues.append(f'invalid_decision:{decision}')
    if release_gate and release_gate not in ('pass', 'stop'):
        issues.append(f'invalid_release_gate:{release_gate}')

    total = as_int(values, 'FIRSTBOOT_HANDOFF_FRESHNESS_TOTAL_ARTIFACTS', issues)
    required_verified = as_int(values, 'FIRSTBOOT_HANDOFF_FRESHNESS_REQUIRED_VERIFIED', issues)
    fresh_required = as_int(values, 'FIRSTBOOT_HANDOFF_FRESHNESS_FRESH_REQUIRED_VERIFIED', issues)
    blocker_count = as_int(values, 'FIRSTBOOT_HANDOFF_FRESHNESS_BLOCKER_COUNT', issues)
    max_age = as_int(values, 'FIRSTBOOT_HANDOFF_FRESHNESS_MAX_AGE_MINUTES', issues, minimum=1)

    if fresh_required > required_verified:
        issues.append('fresh_required_exceeds_required_verified')
    if required_verified > total:
        issues.append('required_verified_exceeds_total')
    if ok == '1' and decision != 'approved':
        issues.append('ok_decision_mismatch')
    if ok == '1' and release_gate != 'pass':
        issues.append('ok_release_gate_mismatch')
    if ok == '0' and release_gate == 'pass':
        issues.append('failed_summary_passes_release_gate')
    if blocker_count == 0 and blockers_text not in ('none', ''):
        issues.append('blocker_count_text_mismatch')
    if blocker_count > 0 and blockers_text in ('none', ''):
        issues.append('missing_blocker_labels')

    smoke_ok = not issues and ok == '1' and decision == 'approved' and release_gate == 'pass'
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_handoff_summary_smoke',
        'created_utc': utc_now(),
        'ok': smoke_ok,
        'decision': 'approved' if smoke_ok else 'deferred',
        'release_gate': 'pass' if smoke_ok else 'stop',
        'source_component': component or 'missing',
        'source_created_utc': created or 'missing',
        'source_input': values.get('FIRSTBOOT_HANDOFF_FRESHNESS_INPUT', 'missing'),
        'source_values': {
            'ok': ok or 'missing',
            'decision': decision or 'missing',
            'release_gate': release_gate or 'missing',
            'max_age_minutes': max_age,
            'total_artifacts': total,
            'required_verified': required_verified,
            'fresh_required_verified': fresh_required,
            'blocker_count': blocker_count,
        },
        'blockers': sorted(set(issues)),
        'operator_next_steps': operator_next_steps(smoke_ok),
        'privacy_scope': 'aggregate_release_gate_handoff_summary_smoke_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': (
            'read-only summary smoke check; no host, VM, firewall, service, network, model, dataset, restore, '
            'approval, or firstboot state was changed'
        ),
        'rollback_note': (
            'remove generated smoke artifacts or stop calling this additive helper; upstream freshness JSON, Markdown, '
            'and summary evidence remain unchanged'
        ),
    }


def operator_next_steps(ok: bool) -> list[str]:
    if ok:
        return [
            'Use this smoke artifact as a lightweight release-gate input beside the authoritative freshness JSON.',
            'Keep the full freshness JSON or Markdown available for audit and manager handoff review.',
        ]
    return [
        'Regenerate handoff freshness evidence before promotion and inspect the authoritative freshness JSON.',
        'Do not treat malformed, missing, contradictory, or deferred summary values as release approval.',
    ]


def render_markdown(report: Dict[str, Any]) -> str:
    values = report['source_values']
    lines = [
        '# Firstboot release-gate handoff summary smoke check',
        '',
        f"- Decision: `{report['decision']}`",
        f"- Release gate: `{report['release_gate']}`",
        f"- Created UTC: `{report['created_utc']}`",
        f"- Source component: `{report['source_component']}`",
        f"- Source created UTC: `{report['source_created_utc']}`",
        f"- Privacy scope: `{report['privacy_scope']}`",
        '',
        '## Source values',
        '',
        '| Field | Value |',
        '| --- | --- |',
    ]
    for key in sorted(values):
        lines.append(f'| {key} | `{values[key]}` |')
    lines.extend(['', '## Blockers', ''])
    if report['blockers']:
        lines.extend(f'- `{blocker}`' for blocker in report['blockers'])
    else:
        lines.append('- None')
    lines.extend([
        '',
        '## Operator next steps',
        '',
        *[f'- {step}' for step in report['operator_next_steps']],
        '',
        '## Privacy and safety',
        '',
        f"- Safe default: {report['safe_default']}",
        f"- Privacy exclusions: {', '.join(report['privacy_exclusions'])}",
        '',
        '## Rollback',
        '',
        report['rollback_note'],
        '',
    ])
    return '\n'.join(lines)


def write_output(path: Path, report: Dict[str, Any], output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == 'markdown':
        path.write_text(render_markdown(report), encoding='utf-8')
        return
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Smoke-check aggregate firstboot handoff freshness summary evidence.')
    parser.add_argument('--input', default=str(DEFAULT_INPUT), help='Path to handoff freshness .summary.env evidence.')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--require-pass', action='store_true', help='Exit non-zero unless the summary smoke check passes.')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    values, blockers = parse_summary_env(Path(args.input))
    report = validate_summary(values, blockers)
    write_output(Path(args.output), report, args.format)
    print(json.dumps({'decision': report['decision'], 'format': args.format, 'ok': report['ok'], 'output': args.output}, sort_keys=True))
    return 0 if report['ok'] or not args.require_pass else 10


if __name__ == '__main__':
    sys.exit(main())
