#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate handoff status reader.
# Purpose: render aggregate-only smoke evidence for safe operator terminal review.

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

DEFAULT_INPUT = Path('/var/log/firstboot_release_gate.handoff_summary_smoke.json')
EXPECTED_COMPONENT = 'firstboot_release_gate_handoff_summary_smoke'
EXPECTED_PRIVACY_SCOPE = 'aggregate_release_gate_handoff_summary_smoke_only'
PRIVACY_EXCLUDED = ('raw telemetry', 'raw logs', 'packets', 'captures', 'private identifiers', 'model binaries', 'datasets')


def utc_now(epoch: Optional[float] = None) -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() if epoch is None else epoch))


def load_json(path: Path) -> tuple[dict[str, Any], list[str]]:
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}, [f'missing_smoke_json:{path}']
    except UnicodeDecodeError as exc:
        return {}, [f'invalid_smoke_json_encoding:{exc.reason}']
    except json.JSONDecodeError as exc:
        return {}, [f'invalid_smoke_json:{exc.msg}']
    if not isinstance(payload, dict):
        return {}, ['invalid_smoke_json:not_object']
    return payload, []


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ''):
        return []
    return [str(value)]


def validate_smoke(payload: dict[str, Any], initial_blockers: list[str]) -> dict[str, Any]:
    blockers = list(initial_blockers)
    component = payload.get('component', 'missing')
    privacy_scope = payload.get('privacy_scope', 'missing')
    ok = payload.get('ok')
    decision = payload.get('decision', 'missing')
    release_gate = payload.get('release_gate', 'missing')
    source_values = payload.get('source_values') if isinstance(payload.get('source_values'), dict) else {}
    source_blockers = as_list(payload.get('blockers'))

    if payload:
        if component != EXPECTED_COMPONENT:
            blockers.append(f'component_mismatch:{component}')
        if privacy_scope != EXPECTED_PRIVACY_SCOPE:
            blockers.append(f'privacy_scope_mismatch:{privacy_scope}')
        if not isinstance(ok, bool):
            blockers.append('invalid_ok_type')
        if decision not in ('approved', 'deferred'):
            blockers.append(f'invalid_decision:{decision}')
        if release_gate not in ('pass', 'stop'):
            blockers.append(f'invalid_release_gate:{release_gate}')
        if ok is True and decision != 'approved':
            blockers.append('ok_decision_mismatch')
        if ok is True and release_gate != 'pass':
            blockers.append('ok_release_gate_mismatch')
        if ok is False and release_gate == 'pass':
            blockers.append('failed_smoke_passes_release_gate')
        if ok is True and source_blockers:
            blockers.append('passing_smoke_contains_blockers')
        if not isinstance(payload.get('source_values'), dict):
            blockers.append('missing_source_values')

    status_ok = not blockers and ok is True and decision == 'approved' and release_gate == 'pass'
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_handoff_status_reader',
        'created_utc': utc_now(),
        'ok': status_ok,
        'decision': 'approved' if status_ok else 'deferred',
        'release_gate': 'pass' if status_ok else 'stop',
        'source_component': component,
        'source_created_utc': payload.get('created_utc', 'missing'),
        'source_decision': decision,
        'source_release_gate': release_gate,
        'source_values': {
            'fresh_required_verified': source_values.get('fresh_required_verified', 'missing'),
            'required_verified': source_values.get('required_verified', 'missing'),
            'total_artifacts': source_values.get('total_artifacts', 'missing'),
            'blocker_count': source_values.get('blocker_count', 'missing'),
        },
        'blockers': sorted(set(blockers + source_blockers)),
        'operator_summary': operator_summary(status_ok, decision, release_gate, source_blockers),
        'operator_next_steps': operator_next_steps(status_ok),
        'privacy_scope': 'aggregate_release_gate_handoff_status_reader_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': 'read-only terminal status renderer; no live system state was changed',
        'rollback_note': 'remove this optional reader or stop packaging it; authoritative handoff artifacts remain unchanged',
    }


def operator_summary(ok: bool, decision: Any, release_gate: Any, source_blockers: list[str]) -> str:
    if ok:
        return 'Firstboot handoff smoke evidence is approved and ready for release or operator handoff review.'
    if source_blockers:
        return f'Firstboot handoff smoke evidence is deferred with {len(source_blockers)} source blocker(s).'
    return f'Firstboot handoff smoke evidence is not approved: decision={decision}, release_gate={release_gate}.'


def operator_next_steps(ok: bool) -> list[str]:
    if ok:
        return [
            'Proceed only if the full release workflow and branch protection checks are also green.',
            'Keep authoritative JSON and Markdown artifacts attached to release or recovery evidence.',
        ]
    return [
        'Inspect firstboot_release_gate.handoff_summary_smoke.json and upstream freshness JSON before promotion.',
        'Regenerate firstboot handoff evidence after repairing stale, malformed, missing, or deferred artifacts.',
        'Do not use this compact reader as an override for failed release-gate evidence.',
    ]


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"decision={report['decision']}",
        f"release_gate={report['release_gate']}",
        f"source_component={report['source_component']}",
        f"source_created_utc={report['source_created_utc']}",
        f"summary={report['operator_summary']}",
    ]
    blockers = report['blockers']
    lines.append('blockers=none' if not blockers else 'blockers=' + ','.join(blockers))
    return '\n'.join(lines) + '\n'


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        '# Firstboot release-gate handoff terminal status',
        '',
        f"- Decision: `{report['decision']}`",
        f"- Release gate: `{report['release_gate']}`",
        f"- Source component: `{report['source_component']}`",
        f"- Source created UTC: `{report['source_created_utc']}`",
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
    if report['blockers']:
        lines.extend(f'- `{blocker}`' for blocker in report['blockers'])
    else:
        lines.append('- None')
    lines.extend(['', '## Operator next steps', ''])
    lines.extend(f'- {step}' for step in report['operator_next_steps'])
    lines.extend(['', '## Privacy and safety', '', f"- Safe default: {report['safe_default']}", f"- Privacy exclusions: {', '.join(report['privacy_exclusions'])}", '', '## Rollback', '', report['rollback_note'], ''])
    return '\n'.join(lines)


def env_escape(value: Any) -> str:
    text = str(value)
    return "'" + text.replace("'", "'\\''") + "'"


def render_summary_env(report: dict[str, Any]) -> str:
    blockers = report['blockers']
    source_values = report['source_values']
    values = {
        'FIRSTBOOT_HANDOFF_STATUS_READER_OK': '1' if report['ok'] else '0',
        'FIRSTBOOT_HANDOFF_STATUS_READER_DECISION': report['decision'],
        'FIRSTBOOT_HANDOFF_STATUS_READER_RELEASE_GATE': report['release_gate'],
        'FIRSTBOOT_HANDOFF_STATUS_READER_SOURCE_COMPONENT': report['source_component'],
        'FIRSTBOOT_HANDOFF_STATUS_READER_SOURCE_CREATED_UTC': report['source_created_utc'],
        'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKER_COUNT': len(blockers),
        'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKERS': 'none' if not blockers else ','.join(blockers),
        'FIRSTBOOT_HANDOFF_STATUS_READER_FRESH_REQUIRED_VERIFIED': source_values.get('fresh_required_verified', 'missing'),
        'FIRSTBOOT_HANDOFF_STATUS_READER_REQUIRED_VERIFIED': source_values.get('required_verified', 'missing'),
        'FIRSTBOOT_HANDOFF_STATUS_READER_TOTAL_ARTIFACTS': source_values.get('total_artifacts', 'missing'),
        'FIRSTBOOT_HANDOFF_STATUS_READER_SOURCE_BLOCKER_COUNT': source_values.get('blocker_count', 'missing'),
        'FIRSTBOOT_HANDOFF_STATUS_READER_PRIVACY_SCOPE': report['privacy_scope'],
    }
    return ''.join(f'{key}={env_escape(value)}\n' for key, value in values.items())


def write_summary_env(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_summary_env(report), encoding='utf-8')


def render(report: dict[str, Any], output_format: str) -> str:
    if output_format == 'json':
        return json.dumps(report, indent=2, sort_keys=True) + '\n'
    if output_format == 'markdown':
        return render_markdown(report)
    return render_text(report)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Render compact aggregate firstboot handoff smoke status for operators.')
    parser.add_argument('--input', default=str(DEFAULT_INPUT), help='Path to handoff summary smoke JSON evidence.')
    parser.add_argument('--format', choices=('text', 'json', 'markdown'), default='text')
    parser.add_argument('--output', help='Optional output path; stdout is used when omitted.')
    parser.add_argument('--summary', help='Optional shell-friendly .env summary output path.')
    parser.add_argument('--require-pass', action='store_true', help='Exit non-zero unless the compact status is approved.')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    payload, blockers = load_json(Path(args.input))
    report = validate_smoke(payload, blockers)
    rendered = render(report, args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding='utf-8')
    else:
        print(rendered, end='')
    if args.summary:
        write_summary_env(report, Path(args.summary))
    if args.require_pass and not report['ok']:
        return 10
    return 0


if __name__ == '__main__':
    sys.exit(main())
