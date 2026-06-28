#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate handoff env policy validator.
# Purpose: validate aggregate-only status-reader summary evidence for safe release review.

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

DEFAULT_INPUT = Path('/var/log/firstboot_release_gate.handoff_status_reader.summary.env')
EXPECTED_PRIVACY_SCOPE = 'aggregate_release_gate_handoff_status_reader_only'
SUMMARY_PREFIX = 'FIRSTBOOT_HANDOFF_ENV_POLICY'
REQUIRED_KEYS = {
    'FIRSTBOOT_HANDOFF_STATUS_READER_OK',
    'FIRSTBOOT_HANDOFF_STATUS_READER_DECISION',
    'FIRSTBOOT_HANDOFF_STATUS_READER_RELEASE_GATE',
    'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKER_COUNT',
    'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKERS',
    'FIRSTBOOT_HANDOFF_STATUS_READER_TOTAL_ARTIFACTS',
    'FIRSTBOOT_HANDOFF_STATUS_READER_PRIVACY_SCOPE',
}
PRIVACY_EXCLUDED = ('raw telemetry', 'raw logs', 'packets', 'captures', 'private identifiers', 'model binaries', 'datasets')


def utc_now(epoch: Optional[float] = None) -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() if epoch is None else epoch))


def shell_quote(value: object) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def read_env(path: Path) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    issues: list[str] = []
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except FileNotFoundError:
        return {}, [f'missing_summary_env:{path}']
    except UnicodeDecodeError as exc:
        return {}, [f'invalid_summary_env_encoding:{exc.reason}']
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if '=' not in stripped:
            issues.append(f'invalid_summary_line:{index}')
            continue
        key, value = stripped.split('=', 1)
        if not key.startswith('FIRSTBOOT_HANDOFF_STATUS_READER_'):
            issues.append(f'unexpected_summary_key:{key}')
            continue
        if not (value.startswith("'") and value.endswith("'")):
            issues.append(f'invalid_summary_value:{key}')
            continue
        values[key] = value[1:-1].replace("'\\''", "'")
    return values, issues


def to_nonnegative_int(values: dict[str, str], key: str, issues: list[str], default: str = 'missing') -> int | None:
    value = values.get(key, default)
    try:
        parsed = int(value)
    except ValueError:
        issues.append(f'invalid_integer:{key}')
        return None
    if parsed < 0:
        issues.append(f'negative_integer:{key}')
        return None
    return parsed


def build_report(values: dict[str, str], initial_issues: list[str]) -> dict[str, Any]:
    issues = list(initial_issues)
    for key in sorted(REQUIRED_KEYS - set(values)):
        issues.append(f'missing_required_key:{key}')

    ok_value = values.get('FIRSTBOOT_HANDOFF_STATUS_READER_OK', 'missing')
    decision = values.get('FIRSTBOOT_HANDOFF_STATUS_READER_DECISION', 'missing')
    release_gate = values.get('FIRSTBOOT_HANDOFF_STATUS_READER_RELEASE_GATE', 'missing')
    privacy_scope = values.get('FIRSTBOOT_HANDOFF_STATUS_READER_PRIVACY_SCOPE', 'missing')
    blockers_text = values.get('FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKERS', 'missing')
    blocker_count = to_nonnegative_int(values, 'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKER_COUNT', issues)
    total_artifacts = to_nonnegative_int(values, 'FIRSTBOOT_HANDOFF_STATUS_READER_TOTAL_ARTIFACTS', issues)

    if ok_value not in ('0', '1'):
        issues.append(f'invalid_ok_value:{ok_value}')
    if decision not in ('approved', 'deferred'):
        issues.append(f'invalid_decision:{decision}')
    if release_gate not in ('pass', 'stop'):
        issues.append(f'invalid_release_gate:{release_gate}')
    if privacy_scope != EXPECTED_PRIVACY_SCOPE:
        issues.append(f'privacy_scope_mismatch:{privacy_scope}')
    if ok_value == '1' and decision != 'approved':
        issues.append('ok_decision_mismatch')
    if ok_value == '1' and release_gate != 'pass':
        issues.append('ok_release_gate_mismatch')
    if ok_value == '0' and release_gate == 'pass':
        issues.append('failed_summary_passes_release_gate')
    if blocker_count == 0 and blockers_text not in ('none', ''):
        issues.append('blocker_count_zero_but_blockers_present')
    if blocker_count and blockers_text in ('none', ''):
        issues.append('blocker_count_positive_but_blockers_missing')
    if total_artifacts == 0:
        issues.append('no_handoff_artifacts_reported')

    approved = not issues and ok_value == '1' and decision == 'approved' and release_gate == 'pass'
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_handoff_env_policy',
        'created_utc': utc_now(),
        'ok': approved,
        'decision': 'approved' if approved else 'deferred',
        'release_gate': 'pass' if approved else 'stop',
        'source_decision': decision,
        'source_release_gate': release_gate,
        'source_privacy_scope': privacy_scope,
        'source_values': {
            'ok': ok_value,
            'blocker_count': blocker_count if blocker_count is not None else 'invalid',
            'blockers': blockers_text,
            'total_artifacts': total_artifacts if total_artifacts is not None else 'invalid',
            'fresh_required_verified': values.get('FIRSTBOOT_HANDOFF_STATUS_READER_FRESH_REQUIRED_VERIFIED', 'missing'),
            'required_verified': values.get('FIRSTBOOT_HANDOFF_STATUS_READER_REQUIRED_VERIFIED', 'missing'),
        },
        'blockers': sorted(set(issues)),
        'operator_summary': 'Status-reader summary env is approved for aggregate handoff policy review.' if approved else f'Status-reader summary env is deferred with {len(set(issues))} blocker(s).',
        'operator_next_steps': operator_next_steps(approved),
        'privacy_scope': 'aggregate_release_gate_handoff_env_policy_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': 'read-only summary evidence validator; no live system state was changed',
        'rollback_note': 'remove this optional validator or stop packaging it; upstream JSON and Markdown evidence remain authoritative',
    }


def operator_next_steps(ok: bool) -> list[str]:
    if ok:
        return [
            'Use this compact signal only with required CI, review, and branch-protection evidence.',
            'Keep upstream JSON and Markdown artifacts as authoritative handoff evidence.',
        ]
    return [
        'Regenerate status-reader summary evidence after repairing upstream handoff artifacts.',
        'Inspect firstboot_release_gate.handoff_status_reader.json for detailed compact status.',
        'Do not treat shell-friendly summary evidence as an override for failed release gates.',
    ]


def render_text(report: dict[str, Any]) -> str:
    blockers = report['blockers']
    return '\n'.join([
        f"decision={report['decision']}",
        f"release_gate={report['release_gate']}",
        f"summary={report['operator_summary']}",
        'blockers=none' if not blockers else 'blockers=' + ','.join(blockers),
    ]) + '\n'


def render_summary_env(report: dict[str, Any]) -> str:
    blockers = ','.join(report['blockers']) if report['blockers'] else 'none'
    values = {
        f'{SUMMARY_PREFIX}_OK': '1' if report['ok'] else '0',
        f'{SUMMARY_PREFIX}_DECISION': report['decision'],
        f'{SUMMARY_PREFIX}_RELEASE_GATE': report['release_gate'],
        f'{SUMMARY_PREFIX}_SOURCE_COMPONENT': report['component'],
        f'{SUMMARY_PREFIX}_SOURCE_CREATED_UTC': report['created_utc'],
        f'{SUMMARY_PREFIX}_SOURCE_DECISION': report['source_decision'],
        f'{SUMMARY_PREFIX}_SOURCE_RELEASE_GATE': report['source_release_gate'],
        f'{SUMMARY_PREFIX}_SOURCE_PRIVACY_SCOPE': report['source_privacy_scope'],
        f'{SUMMARY_PREFIX}_BLOCKER_COUNT': len(report['blockers']),
        f'{SUMMARY_PREFIX}_BLOCKERS': blockers,
        f'{SUMMARY_PREFIX}_TOTAL_ARTIFACTS': report['source_values']['total_artifacts'],
        f'{SUMMARY_PREFIX}_PRIVACY_SCOPE': report['privacy_scope'],
        f'{SUMMARY_PREFIX}_SAFE_DEFAULT': report['safe_default'],
    }
    return ''.join(f'{key}={shell_quote(value)}\n' for key, value in values.items())


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        '# Firstboot release-gate handoff env policy',
        '',
        f"- Decision: `{report['decision']}`",
        f"- Release gate: `{report['release_gate']}`",
        f"- Privacy scope: `{report['privacy_scope']}`",
        '',
        '## Operator summary',
        '',
        report['operator_summary'],
        '',
        '## Aggregate source values',
        '',
        '| Field | Value |',
        '| --- | --- |',
    ]
    for key, value in sorted(report['source_values'].items()):
        lines.append(f'| {key} | `{value}` |')
    lines.extend(['', '## Blockers', ''])
    lines.extend(f'- `{item}`' for item in report['blockers']) if report['blockers'] else lines.append('- None')
    lines.extend(['', '## Operator next steps', ''])
    lines.extend(f'- {step}' for step in report['operator_next_steps'])
    lines.extend(['', '## Privacy and safety', '', f"- Safe default: {report['safe_default']}", f"- Privacy exclusions: {', '.join(report['privacy_exclusions'])}", '', '## Rollback', '', report['rollback_note'], ''])
    return '\n'.join(lines)


def render(report: dict[str, Any], output_format: str) -> str:
    if output_format == 'json':
        return json.dumps(report, indent=2, sort_keys=True) + '\n'
    if output_format == 'markdown':
        return render_markdown(report)
    return render_text(report)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Validate aggregate firstboot handoff status-reader summary evidence.')
    parser.add_argument('--input', default=str(DEFAULT_INPUT), help='Path to status-reader summary env evidence.')
    parser.add_argument('--format', choices=('text', 'json', 'markdown'), default='text')
    parser.add_argument('--output', help='Optional output path; stdout is used when omitted.')
    parser.add_argument('--summary', help='Optional shell-safe summary env sidecar output path.')
    parser.add_argument('--require-pass', action='store_true', help='Exit non-zero unless summary policy evidence is approved.')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    values, issues = read_env(Path(args.input))
    report = build_report(values, issues)
    rendered = render(report, args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding='utf-8')
    else:
        print(rendered, end='')
    if args.summary:
        summary_path = Path(args.summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(render_summary_env(report), encoding='utf-8')
    if args.require_pass and not report['ok']:
        return 10
    return 0


if __name__ == '__main__':
    sys.exit(main())
