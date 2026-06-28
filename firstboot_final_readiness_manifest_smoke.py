#!/usr/bin/env python3
# MINC - Defensive final-readiness manifest summary smoke gate.
# Purpose: validate aggregate final-readiness manifest .summary.env evidence without sourcing shell.

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_INPUT = Path('/var/log/firstboot_release_gate.final_readiness_manifest.summary.env')
SOURCE_PREFIX = 'FIRSTBOOT_FINAL_READINESS_MANIFEST_'
SUMMARY_PREFIX = 'FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE'
EXPECTED_SOURCE_COMPONENT = 'firstboot_final_readiness_manifest'
EXPECTED_SOURCE_PRIVACY_SCOPE = 'aggregate_firstboot_final_readiness_smoke_only'
EXPECTED_PRIVACY_SCOPE = 'aggregate_firstboot_final_readiness_manifest_only'
REQUIRED_KEYS = {
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_OK',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_DECISION',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_RELEASE_GATE',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_COMPONENT',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_DECISION',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_RELEASE_GATE',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_PRIVACY_SCOPE',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_BLOCKER_COUNT',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_BLOCKERS',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_EXPECTED_ARTIFACTS',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_PRIVACY_SCOPE',
    'FIRSTBOOT_FINAL_READINESS_MANIFEST_SAFE_DEFAULT',
}


def shell_quote(value: object) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def read_env(path: Path) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    issues: list[str] = []
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except FileNotFoundError:
        return {}, [f'missing_final_readiness_manifest_summary:{path}']
    except UnicodeDecodeError as exc:
        return {}, [f'invalid_final_readiness_manifest_summary_encoding:{exc.reason}']

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


def as_nonnegative_int(values: dict[str, str], key: str, issues: list[str]) -> int | None:
    try:
        parsed = int(values.get(key, 'missing'))
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

    ok_value = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_OK', 'missing')
    decision = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_DECISION', 'missing')
    release_gate = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_RELEASE_GATE', 'missing')
    source_component = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_COMPONENT', 'missing')
    source_decision = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_DECISION', 'missing')
    source_release_gate = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_RELEASE_GATE', 'missing')
    source_privacy_scope = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_SOURCE_PRIVACY_SCOPE', 'missing')
    privacy_scope = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_PRIVACY_SCOPE', 'missing')
    safe_default = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_SAFE_DEFAULT', 'missing')
    blockers = values.get('FIRSTBOOT_FINAL_READINESS_MANIFEST_BLOCKERS', 'missing')
    blocker_count = as_nonnegative_int(values, 'FIRSTBOOT_FINAL_READINESS_MANIFEST_BLOCKER_COUNT', issues)
    expected_artifacts = as_nonnegative_int(values, 'FIRSTBOOT_FINAL_READINESS_MANIFEST_EXPECTED_ARTIFACTS', issues)

    if ok_value not in ('0', '1'):
        issues.append(f'invalid_ok_value:{ok_value}')
    if decision not in ('approved', 'deferred'):
        issues.append(f'invalid_decision:{decision}')
    if release_gate not in ('pass', 'stop'):
        issues.append(f'invalid_release_gate:{release_gate}')
    if source_component != EXPECTED_SOURCE_COMPONENT:
        issues.append(f'source_component_mismatch:{source_component}')
    if source_decision not in ('approved', 'deferred'):
        issues.append(f'invalid_source_decision:{source_decision}')
    if source_release_gate not in ('pass', 'stop'):
        issues.append(f'invalid_source_release_gate:{source_release_gate}')
    if source_privacy_scope != EXPECTED_SOURCE_PRIVACY_SCOPE:
        issues.append(f'source_privacy_scope_mismatch:{source_privacy_scope}')
    if privacy_scope != EXPECTED_PRIVACY_SCOPE:
        issues.append(f'privacy_scope_mismatch:{privacy_scope}')
    if 'read-only' not in safe_default:
        issues.append('safe_default_missing_read_only_contract')
    if ok_value == '1' and decision != 'approved':
        issues.append('ok_decision_mismatch')
    if ok_value == '1' and release_gate != 'pass':
        issues.append('ok_release_gate_mismatch')
    if ok_value == '0' and release_gate == 'pass':
        issues.append('failed_summary_passes_release_gate')
    if blocker_count == 0 and blockers not in ('none', ''):
        issues.append('blocker_count_zero_but_blockers_present')
    if blocker_count and blockers in ('none', ''):
        issues.append('blocker_count_positive_but_blockers_missing')
    if expected_artifacts == 0:
        issues.append('no_expected_artifacts_reported')

    unique_issues = sorted(set(issues))
    approved = not unique_issues and ok_value == '1' and decision == 'approved' and release_gate == 'pass'
    return {
        'schema_version': 1,
        'component': 'firstboot_final_readiness_manifest_smoke',
        'ok': approved,
        'decision': 'approved' if approved else 'deferred',
        'release_gate': 'pass' if approved else 'stop',
        'source_values': {
            'ok': ok_value,
            'decision': decision,
            'release_gate': release_gate,
            'source_component': source_component,
            'source_decision': source_decision,
            'source_release_gate': source_release_gate,
            'source_privacy_scope': source_privacy_scope,
            'privacy_scope': privacy_scope,
            'blocker_count': blocker_count if blocker_count is not None else 'invalid',
            'blockers': blockers,
            'expected_artifacts': expected_artifacts if expected_artifacts is not None else 'invalid',
        },
        'blockers': unique_issues,
        'operator_summary': 'Final readiness manifest smoke evidence is approved.' if approved else f'Final readiness manifest smoke evidence is deferred with {len(unique_issues)} blocker(s).',
        'privacy_scope': 'aggregate_firstboot_final_readiness_manifest_smoke_only',
        'safe_default': 'read-only final readiness manifest smoke helper; no live system state was changed',
        'rollback_note': 'remove this optional manifest smoke helper or stop packaging it; final-readiness manifest JSON, Markdown, and summary evidence remain authoritative',
    }


def render_summary_env(report: dict[str, Any]) -> str:
    blockers = ','.join(report['blockers']) if report['blockers'] else 'none'
    values = {
        f'{SUMMARY_PREFIX}_OK': '1' if report['ok'] else '0',
        f'{SUMMARY_PREFIX}_DECISION': report['decision'],
        f'{SUMMARY_PREFIX}_RELEASE_GATE': report['release_gate'],
        f'{SUMMARY_PREFIX}_SOURCE_COMPONENT': report['component'],
        f'{SUMMARY_PREFIX}_SOURCE_DECISION': report['source_values']['decision'],
        f'{SUMMARY_PREFIX}_SOURCE_RELEASE_GATE': report['source_values']['release_gate'],
        f'{SUMMARY_PREFIX}_SOURCE_PRIVACY_SCOPE': report['source_values']['privacy_scope'],
        f'{SUMMARY_PREFIX}_BLOCKER_COUNT': len(report['blockers']),
        f'{SUMMARY_PREFIX}_BLOCKERS': blockers,
        f'{SUMMARY_PREFIX}_EXPECTED_ARTIFACTS': report['source_values']['expected_artifacts'],
        f'{SUMMARY_PREFIX}_PRIVACY_SCOPE': report['privacy_scope'],
        f'{SUMMARY_PREFIX}_SAFE_DEFAULT': report['safe_default'],
    }
    return ''.join(f'{key}={shell_quote(value)}\n' for key, value in values.items())


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        '# Firstboot final readiness manifest smoke',
        '',
        f"- Decision: `{report['decision']}`",
        f"- Release gate: `{report['release_gate']}`",
        f"- Privacy scope: `{report['privacy_scope']}`",
        '',
        '## Operator summary',
        '',
        report['operator_summary'],
        '',
        '## Blockers',
        '',
    ]
    lines.extend(f'- `{item}`' for item in report['blockers']) if report['blockers'] else lines.append('- None')
    lines.extend(['', '## Rollback', '', report['rollback_note'], ''])
    return '\n'.join(lines)


def render(report: dict[str, Any], output_format: str) -> str:
    if output_format == 'json':
        return json.dumps(report, indent=2, sort_keys=True) + '\n'
    if output_format == 'markdown':
        return render_markdown(report)
    blockers = 'none' if not report['blockers'] else ','.join(report['blockers'])
    return f"decision={report['decision']}\nrelease_gate={report['release_gate']}\nblockers={blockers}\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Validate passive aggregate firstboot final-readiness manifest summary evidence.')
    parser.add_argument('--input', default=str(DEFAULT_INPUT))
    parser.add_argument('--format', choices=('text', 'json', 'markdown'), default='text')
    parser.add_argument('--output')
    parser.add_argument('--summary', help='Optional shell-safe summary env sidecar output path.')
    parser.add_argument('--require-pass', action='store_true')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    values, issues = read_env(Path(args.input))
    report = build_report(values, issues)
    rendered = render(report, args.format)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding='utf-8')
    else:
        print(rendered, end='')
    if args.summary:
        summary = Path(args.summary)
        summary.parent.mkdir(parents=True, exist_ok=True)
        summary.write_text(render_summary_env(report), encoding='utf-8')
    if args.require_pass and not report['ok']:
        return 10
    return 0


if __name__ == '__main__':
    sys.exit(main())
