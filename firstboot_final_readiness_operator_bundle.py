#!/usr/bin/env python3
# MINC - Passive firstboot final-readiness operator bundle helper.
# Reads aggregate operator-verdict summary evidence and writes derived handoff bundle evidence only.

from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_INPUT = Path('/var/log/firstboot_release_gate.final_readiness_operator_verdict.summary.env')
SOURCE_PREFIX = 'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_'
SUMMARY_PREFIX = 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE'
EXPECTED_SOURCE_COMPONENT = 'firstboot_final_readiness_operator_verdict'
EXPECTED_SOURCE_PRIVACY_SCOPE = 'aggregate_firstboot_final_readiness_contract_seal_smoke_only'
EXPECTED_OPERATOR_PRIVACY_SCOPE = 'aggregate_firstboot_final_readiness_operator_verdict_only'
EXPECTED_PRIVACY_SCOPE = 'aggregate_firstboot_final_readiness_operator_bundle_only'
EXPECTED_ARTIFACTS = (
    '/var/log/firstboot_release_gate.final_readiness_operator_verdict.json',
    '/var/log/firstboot_release_gate.final_readiness_operator_verdict.md',
    '/var/log/firstboot_release_gate.final_readiness_operator_verdict.summary.env',
)
UPSTREAM_CHAIN = (
    'firstboot_release_gate',
    'firstboot_release_gate_status',
    'firstboot_release_gate_bundle_manifest',
    'firstboot_release_gate_operator_digest',
    'firstboot_release_gate_handoff_index',
    'firstboot_release_gate_handoff_verify',
    'firstboot_release_gate_handoff_freshness',
    'firstboot_release_gate_handoff_summary_smoke',
    'firstboot_release_gate_handoff_status_reader',
    'firstboot_release_gate_handoff_env_policy',
    'firstboot_release_gate_handoff_env_policy_smoke',
    'firstboot_final_readiness',
    'firstboot_final_readiness_smoke',
    'firstboot_final_readiness_manifest',
    'firstboot_final_readiness_manifest_smoke',
    'firstboot_final_readiness_contract_seal',
    'firstboot_final_readiness_contract_seal_smoke',
    'firstboot_final_readiness_operator_verdict',
)
REQUIRED_KEYS = {
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_OK',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_DECISION',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_RELEASE_GATE',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_VERDICT',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SOURCE_COMPONENT',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SOURCE_PRIVACY_SCOPE',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_BLOCKER_COUNT',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_BLOCKERS',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_EXPECTED_ARTIFACTS',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_PRIVACY_SCOPE',
    'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SAFE_DEFAULT',
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

    ok_value = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_OK', 'missing')
    decision = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_DECISION', 'missing')
    release_gate = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_RELEASE_GATE', 'missing')
    verdict = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_VERDICT', 'missing')
    source_component = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SOURCE_COMPONENT', 'missing')
    source_privacy_scope = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SOURCE_PRIVACY_SCOPE', 'missing')
    privacy_scope = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_PRIVACY_SCOPE', 'missing')
    safe_default = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SAFE_DEFAULT', 'missing')
    blockers = values.get('FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_BLOCKERS', 'missing')
    blocker_count = parse_count(values, 'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_BLOCKER_COUNT', issues)
    upstream_expected_artifacts = parse_count(values, 'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_EXPECTED_ARTIFACTS', issues)

    if ok_value not in ('0', '1'):
        issues.append(f'invalid_ok_value:{ok_value}')
    if decision not in ('approved', 'deferred'):
        issues.append(f'invalid_decision:{decision}')
    if release_gate not in ('pass', 'stop'):
        issues.append(f'invalid_release_gate:{release_gate}')
    if verdict not in ('promote', 'hold'):
        issues.append(f'invalid_operator_verdict:{verdict}')
    if source_component != EXPECTED_SOURCE_COMPONENT:
        issues.append(f'source_component_mismatch:{source_component}')
    if source_privacy_scope != EXPECTED_SOURCE_PRIVACY_SCOPE:
        issues.append(f'source_privacy_scope_mismatch:{source_privacy_scope}')
    if privacy_scope != EXPECTED_OPERATOR_PRIVACY_SCOPE:
        issues.append(f'privacy_scope_mismatch:{privacy_scope}')
    if 'read-only final readiness operator verdict helper' not in safe_default:
        issues.append('safe_default_mismatch')
    if ok_value == '1' and decision != 'approved':
        issues.append('ok_decision_mismatch')
    if ok_value == '1' and release_gate != 'pass':
        issues.append('ok_release_gate_mismatch')
    if ok_value == '1' and verdict != 'promote':
        issues.append('ok_verdict_mismatch')
    if ok_value == '0' and release_gate == 'pass':
        issues.append('failed_summary_passes_release_gate')
    if verdict == 'promote' and release_gate != 'pass':
        issues.append('promote_without_pass')
    if blocker_count == 0 and blockers not in ('none', ''):
        issues.append('blocker_count_zero_but_blockers_present')
    if blocker_count and blockers in ('none', ''):
        issues.append('blocker_count_positive_but_blockers_missing')
    if upstream_expected_artifacts == 0:
        issues.append('no_upstream_expected_artifacts_reported')

    final_issues = sorted(set(issues))
    approved = not final_issues and ok_value == '1' and decision == 'approved' and release_gate == 'pass' and verdict == 'promote'
    return {
        'schema_version': 1,
        'component': 'firstboot_final_readiness_operator_bundle',
        'ok': approved,
        'decision': 'approved' if approved else 'deferred',
        'release_gate': 'pass' if approved else 'stop',
        'bundle_verdict': 'ready' if approved else 'hold',
        'source_component': source_component,
        'source_privacy_scope': privacy_scope,
        'expected_artifact_count': len(EXPECTED_ARTIFACTS),
        'expected_artifacts': list(EXPECTED_ARTIFACTS),
        'upstream_chain': list(UPSTREAM_CHAIN),
        'upstream_expected_artifacts': upstream_expected_artifacts if upstream_expected_artifacts is not None else 'invalid',
        'blockers': final_issues,
        'operator_summary': 'Firstboot final-readiness operator bundle is ready for release handoff.' if approved else f'Firstboot final-readiness operator bundle is on hold with {len(final_issues)} blocker(s).',
        'privacy_scope': EXPECTED_PRIVACY_SCOPE,
        'safe_default': 'read-only final readiness operator bundle helper; no live system state was changed',
        'rollback_note': 'remove this optional operator bundle helper or stop packaging it; operator verdict evidence remains authoritative',
    }


def render_summary_env(report: dict[str, object]) -> str:
    blockers = ','.join(report['blockers']) if report['blockers'] else 'none'
    values = {
        f'{SUMMARY_PREFIX}_OK': '1' if report['ok'] else '0',
        f'{SUMMARY_PREFIX}_DECISION': report['decision'],
        f'{SUMMARY_PREFIX}_RELEASE_GATE': report['release_gate'],
        f'{SUMMARY_PREFIX}_VERDICT': report['bundle_verdict'],
        f'{SUMMARY_PREFIX}_SOURCE_COMPONENT': report['source_component'],
        f'{SUMMARY_PREFIX}_SOURCE_PRIVACY_SCOPE': report['source_privacy_scope'],
        f'{SUMMARY_PREFIX}_BLOCKER_COUNT': len(report['blockers']),
        f'{SUMMARY_PREFIX}_BLOCKERS': blockers,
        f'{SUMMARY_PREFIX}_EXPECTED_ARTIFACTS': report['expected_artifact_count'],
        f'{SUMMARY_PREFIX}_UPSTREAM_EXPECTED_ARTIFACTS': report['upstream_expected_artifacts'],
        f'{SUMMARY_PREFIX}_PRIVACY_SCOPE': report['privacy_scope'],
        f'{SUMMARY_PREFIX}_SAFE_DEFAULT': report['safe_default'],
    }
    return ''.join(f'{key}={shell_quote(value)}\n' for key, value in values.items())


def render_markdown(report: dict[str, object]) -> str:
    lines = [
        '# Firstboot final readiness operator bundle',
        '',
        f"- Decision: `{report['decision']}`",
        f"- Release gate: `{report['release_gate']}`",
        f"- Bundle verdict: `{report['bundle_verdict']}`",
        f"- Privacy scope: `{report['privacy_scope']}`",
        '',
        '## Operator summary',
        '',
        str(report['operator_summary']),
        '',
        '## Expected handoff artifacts',
        '',
    ]
    lines.extend(f'- `{item}`' for item in report['expected_artifacts'])
    lines.extend(['', '## Upstream evidence chain', ''])
    lines.extend(f'- `{item}`' for item in report['upstream_chain'])
    lines.extend(['', '## Blockers', ''])
    blockers = report['blockers']
    lines.extend(f'- `{item}`' for item in blockers) if blockers else lines.append('- None')
    lines.extend(['', '## Rollback', '', str(report['rollback_note']), ''])
    return '\n'.join(lines)


def render(report: dict[str, object], output_format: str) -> str:
    if output_format == 'json':
        return json.dumps(report, indent=2, sort_keys=True) + '\n'
    if output_format == 'markdown':
        return render_markdown(report)
    blockers = 'none' if not report['blockers'] else ','.join(report['blockers'])
    return f"decision={report['decision']}\nrelease_gate={report['release_gate']}\nbundle_verdict={report['bundle_verdict']}\nblockers={blockers}\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Render passive firstboot final-readiness operator bundle evidence.')
    parser.add_argument('--input', default=str(DEFAULT_INPUT))
    parser.add_argument('--format', choices=('text', 'json', 'markdown'), default='text')
    parser.add_argument('--output')
    parser.add_argument('--summary')
    parser.add_argument('--require-pass', action='store_true')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    values, issues = read_summary(Path(args.input))
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
    raise SystemExit(main())
