#!/usr/bin/env python3
# MINC - Passive firstboot final-readiness operator bundle smoke helper.
# Verifies aggregate operator-bundle summary evidence without changing host or VM state.

from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_INPUT = Path('/var/log/firstboot_release_gate.final_readiness_operator_bundle.summary.env')
SOURCE_PREFIX = 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_'
SUMMARY_PREFIX = 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE'
EXPECTED_SOURCE_COMPONENT = 'firstboot_final_readiness_operator_verdict'
EXPECTED_SOURCE_PRIVACY_SCOPE = 'aggregate_firstboot_final_readiness_operator_verdict_only'
EXPECTED_PRIVACY_SCOPE = 'aggregate_firstboot_final_readiness_operator_bundle_smoke_only'
EXPECTED_ARTIFACTS = (
    '/var/log/firstboot_release_gate.final_readiness_operator_bundle.json',
    '/var/log/firstboot_release_gate.final_readiness_operator_bundle.md',
    '/var/log/firstboot_release_gate.final_readiness_operator_bundle.summary.env',
)
REQUIRED_KEYS = {
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_OK',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_DECISION',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_RELEASE_GATE',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_VERDICT',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SOURCE_COMPONENT',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SOURCE_PRIVACY_SCOPE',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_BLOCKER_COUNT',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_BLOCKERS',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_EXPECTED_ARTIFACTS',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_PRIVACY_SCOPE',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SAFE_DEFAULT',
}


def shell_quote(value: object) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def read_summary(path: Path) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    issues: list[str] = []
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except FileNotFoundError:
        return {}, [f'missing_summary:{path}']
    except UnicodeDecodeError as exc:
        return {}, [f'invalid_summary_encoding:{exc.reason}']

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if '=' not in stripped:
            issues.append(f'invalid_summary_line:{index}')
            continue
        key, value = stripped.split('=', 1)
        if not key.startswith(SOURCE_PREFIX):
            issues.append(f'unexpected_summary_key:{key}')
            continue
        if not (value.startswith("'") and value.endswith("'")):
            issues.append(f'invalid_summary_value:{key}')
            continue
        values[key] = value[1:-1].replace("'\\''", "'")
    return values, issues


def parse_count(values: dict[str, str], key: str, issues: list[str]) -> int | None:
    try:
        parsed = int(values.get(key, 'missing'))
    except ValueError:
        issues.append(f'invalid_integer:{key}')
        return None
    if parsed < 0:
        issues.append(f'negative_integer:{key}')
        return None
    return parsed


def build_report(values: dict[str, str], initial_issues: list[str]) -> dict[str, object]:
    issues = list(initial_issues)
    for key in sorted(REQUIRED_KEYS - set(values)):
        issues.append(f'missing_required_key:{key}')

    ok_value = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_OK', 'missing')
    decision = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_DECISION', 'missing')
    release_gate = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_RELEASE_GATE', 'missing')
    verdict = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_VERDICT', 'missing')
    source_component = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SOURCE_COMPONENT', 'missing')
    source_privacy_scope = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SOURCE_PRIVACY_SCOPE', 'missing')
    privacy_scope = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_PRIVACY_SCOPE', 'missing')
    safe_default = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SAFE_DEFAULT', 'missing')
    blockers = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_BLOCKERS', 'missing')
    blocker_count = parse_count(values, 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_BLOCKER_COUNT', issues)
    expected_artifacts = parse_count(values, 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_EXPECTED_ARTIFACTS', issues)

    if ok_value not in ('0', '1'):
        issues.append(f'invalid_ok_value:{ok_value}')
    if decision not in ('approved', 'deferred'):
        issues.append(f'invalid_decision:{decision}')
    if release_gate not in ('pass', 'stop'):
        issues.append(f'invalid_release_gate:{release_gate}')
    if verdict not in ('ready', 'hold'):
        issues.append(f'invalid_bundle_verdict:{verdict}')
    if source_component != EXPECTED_SOURCE_COMPONENT:
        issues.append(f'source_component_mismatch:{source_component}')
    if source_privacy_scope != EXPECTED_SOURCE_PRIVACY_SCOPE:
        issues.append(f'source_privacy_scope_mismatch:{source_privacy_scope}')
    if privacy_scope != 'aggregate_firstboot_final_readiness_operator_bundle_only':
        issues.append(f'privacy_scope_mismatch:{privacy_scope}')
    if 'read-only final readiness operator bundle helper' not in safe_default:
        issues.append('safe_default_mismatch')
    if ok_value == '1' and decision != 'approved':
        issues.append('ok_decision_mismatch')
    if ok_value == '1' and release_gate != 'pass':
        issues.append('ok_release_gate_mismatch')
    if ok_value == '1' and verdict != 'ready':
        issues.append('ok_verdict_mismatch')
    if ok_value == '0' and release_gate == 'pass':
        issues.append('failed_summary_passes_release_gate')
    if verdict == 'ready' and release_gate != 'pass':
        issues.append('ready_without_pass')
    if blocker_count == 0 and blockers not in ('none', ''):
        issues.append('blocker_count_zero_but_blockers_present')
    if blocker_count and blockers in ('none', ''):
        issues.append('blocker_count_positive_but_blockers_missing')
    if expected_artifacts != 3:
        issues.append(f'expected_artifact_count_mismatch:{expected_artifacts}')

    final_issues = sorted(set(issues))
    approved = not final_issues and ok_value == '1' and decision == 'approved' and release_gate == 'pass' and verdict == 'ready'
    return {
        'schema_version': 1,
        'component': 'firstboot_final_readiness_operator_bundle_smoke',
        'ok': approved,
        'decision': 'approved' if approved else 'deferred',
        'release_gate': 'pass' if approved else 'stop',
        'smoke_verdict': 'pass' if approved else 'hold',
        'source_component': 'firstboot_final_readiness_operator_bundle',
        'source_privacy_scope': privacy_scope,
        'expected_artifact_count': len(EXPECTED_ARTIFACTS),
        'expected_artifacts': list(EXPECTED_ARTIFACTS),
        'blockers': final_issues,
        'operator_summary': 'Firstboot final-readiness operator bundle smoke passed.' if approved else f'Firstboot final-readiness operator bundle smoke is on hold with {len(final_issues)} blocker(s).',
        'privacy_scope': EXPECTED_PRIVACY_SCOPE,
        'safe_default': 'read-only final readiness operator bundle smoke helper; no live system state was changed',
        'rollback_note': 'remove this optional smoke helper or stop packaging it; operator bundle evidence remains available',
    }


def render_summary_env(report: dict[str, object]) -> str:
    blockers = ','.join(report['blockers']) if report['blockers'] else 'none'
    values = {
        f'{SUMMARY_PREFIX}_OK': '1' if report['ok'] else '0',
        f'{SUMMARY_PREFIX}_DECISION': report['decision'],
        f'{SUMMARY_PREFIX}_RELEASE_GATE': report['release_gate'],
        f'{SUMMARY_PREFIX}_VERDICT': report['smoke_verdict'],
        f'{SUMMARY_PREFIX}_SOURCE_COMPONENT': report['source_component'],
        f'{SUMMARY_PREFIX}_SOURCE_PRIVACY_SCOPE': report['source_privacy_scope'],
        f'{SUMMARY_PREFIX}_BLOCKER_COUNT': len(report['blockers']),
        f'{SUMMARY_PREFIX}_BLOCKERS': blockers,
        f'{SUMMARY_PREFIX}_EXPECTED_ARTIFACTS': report['expected_artifact_count'],
        f'{SUMMARY_PREFIX}_PRIVACY_SCOPE': report['privacy_scope'],
        f'{SUMMARY_PREFIX}_SAFE_DEFAULT': report['safe_default'],
    }
    return ''.join(f'{key}={shell_quote(value)}\n' for key, value in values.items())


def render_markdown(report: dict[str, object]) -> str:
    blockers = report['blockers'] or ['none']
    lines = [
        '# Firstboot final readiness operator bundle smoke',
        '',
        f"Smoke verdict: `{report['smoke_verdict']}`",
        f"Release gate: `{report['release_gate']}`",
        f"Decision: `{report['decision']}`",
        f"Source component: `{report['source_component']}`",
        f"Privacy scope: `{report['privacy_scope']}`",
        '',
        '## Blockers',
        '',
    ]
    lines.extend(f'- `{blocker}`' for blocker in blockers)
    lines.extend([
        '',
        '## Expected artifacts',
        '',
    ])
    lines.extend(f'- `{artifact}`' for artifact in report['expected_artifacts'])
    lines.extend([
        '',
        '## Safe default',
        '',
        str(report['safe_default']),
        '',
        '## Rollback',
        '',
        str(report['rollback_note']),
        '',
    ])
    return '\n'.join(lines)


def emit(report: dict[str, object], fmt: str) -> str:
    if fmt == 'json':
        return json.dumps(report, indent=2, sort_keys=True) + '\n'
    if fmt == 'markdown':
        return render_markdown(report)
    return str(report['operator_summary']) + '\n'


def main() -> int:
    parser = argparse.ArgumentParser(description='Smoke-check passive firstboot operator-bundle summary evidence.')
    parser.add_argument('--input', type=Path, default=DEFAULT_INPUT)
    parser.add_argument('--format', choices=('text', 'json', 'markdown'), default='text')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--summary', type=Path, help='Optional shell-safe summary.env output path.')
    parser.add_argument('--require-pass', action='store_true', help='Exit non-zero unless the smoke verdict passes.')
    args = parser.parse_args()

    values, issues = read_summary(args.input)
    report = build_report(values, issues)
    output = emit(report, args.format)

    if args.output:
        args.output.write_text(output, encoding='utf-8')
    else:
        print(output, end='')

    if args.summary:
        args.summary.write_text(render_summary_env(report), encoding='utf-8')

    if args.require_pass and not report['ok']:
        return 10
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
