#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate handoff freshness helper.
# Purpose: fail closed on stale privacy-safe handoff verification evidence before promotion.

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

DEFAULT_INPUT = Path('/var/log/firstboot_release_gate.handoff_verify.json')
DEFAULT_OUTPUT = Path('/var/log/firstboot_release_gate.handoff_freshness.json')
DEFAULT_MAX_AGE_MINUTES = 1440

PRIVACY_EXCLUDED = (
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


def read_json_object(path: Path) -> tuple[Dict[str, Any], list[str]]:
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}, [f'missing_verification:{path}']
    except json.JSONDecodeError as exc:
        return {}, [f'invalid_verification_json:{exc.msg}']
    if not isinstance(payload, dict):
        return {}, ['invalid_verification_json:top-level JSON must be an object']
    return payload, []


def normalize_blockers(blockers: Iterable[str]) -> list[str]:
    return sorted(set(str(blocker) for blocker in blockers if str(blocker)))


def freshness_record(path: Path, now: float, max_age_seconds: int) -> Dict[str, Any]:
    exists = path.exists() and path.is_file()
    mtime = path.stat().st_mtime if exists else None
    age = max(0, int(now - mtime)) if mtime is not None else None
    return {
        'path': str(path),
        'exists': exists,
        'mtime_utc': utc_now(mtime) if mtime is not None else None,
        'age_seconds': age,
        'max_age_seconds': max_age_seconds,
        'fresh': exists and age is not None and age <= max_age_seconds,
    }


def artifact_freshness(record: Dict[str, Any], now: float, max_age_seconds: int) -> Dict[str, Any]:
    path = Path(str(record.get('path', '')))
    result = freshness_record(path, now, max_age_seconds)
    result.update({
        'label': str(record.get('label', 'unknown')),
        'required': bool(record.get('required')),
        'verified': bool(record.get('verified')),
    })
    return result


def build_freshness(input_path: Path, max_age_minutes: int, now: Optional[float] = None) -> Dict[str, Any]:
    current_time = time.time() if now is None else now
    max_age_seconds = max_age_minutes * 60
    verification, blockers = read_json_object(input_path)
    input_record = freshness_record(input_path, current_time, max_age_seconds)

    if max_age_minutes <= 0:
        blockers.append('invalid_freshness_threshold:max_age_minutes_must_be_positive')
    if input_record['exists'] and not input_record['fresh']:
        blockers.append('stale_verification_artifact')

    if verification:
        if verification.get('component') != 'firstboot_release_gate_handoff_verify':
            blockers.append(f'component_mismatch:{verification.get("component", "unknown")}')
        if verification.get('privacy_scope') != 'aggregate_release_gate_handoff_verification_only':
            blockers.append(f'privacy_scope_mismatch:{verification.get("privacy_scope", "unknown")}')
        if verification.get('ok') is not True:
            blockers.append('handoff_verification_not_approved')
        if verification.get('release_gate') != 'pass':
            blockers.append(f'handoff_verification_release_gate:{verification.get("release_gate", "unknown")}')

    artifact_records = []
    artifacts = verification.get('artifacts', []) if verification else []
    if verification and not isinstance(artifacts, list):
        blockers.append('invalid_artifacts:must_be_list')
        artifacts = []

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            blockers.append('invalid_artifact_record:must_be_object')
            continue
        result = artifact_freshness(artifact, current_time, max_age_seconds)
        artifact_records.append(result)
        if result['required'] and result['verified'] and not result['exists']:
            blockers.append(f'missing_verified_artifact:{result["label"]}')
        if result['required'] and result['verified'] and not result['fresh']:
            blockers.append(f'stale_verified_artifact:{result["label"]}')

    fresh_required = sum(1 for item in artifact_records if item['required'] and item['verified'] and item['fresh'])
    required_verified = sum(1 for item in artifact_records if item['required'] and item['verified'])
    blockers = normalize_blockers(blockers)
    ok = not blockers

    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_handoff_freshness',
        'created_utc': utc_now(current_time),
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'input_path': str(input_path),
        'freshness_policy': {
            'max_age_minutes': max_age_minutes,
            'max_age_seconds': max_age_seconds,
            'clock_utc': utc_now(current_time),
        },
        'verification_artifact': input_record,
        'artifact_counts': {
            'total': len(artifact_records),
            'required_verified': required_verified,
            'fresh_required_verified': fresh_required,
        },
        'artifacts': artifact_records,
        'blockers': blockers,
        'manager_summary': manager_summary(ok, fresh_required, required_verified, max_age_minutes),
        'handoff_checklist': handoff_checklist(ok),
        'privacy_scope': 'aggregate_release_gate_handoff_freshness_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': (
            'read-only freshness gate; no host, VM, firewall, service, model, dataset, approval, restore, '
            'network, or firstboot state was changed'
        ),
        'rollback_note': (
            'delete the generated freshness artifact or revert this additive helper, docs, and tests; '
            'upstream handoff verification and release-gate evidence remain unchanged'
        ),
    }


def manager_summary(ok: bool, fresh_required: int, required_verified: int, max_age_minutes: int) -> str:
    if ok:
        return (
            'Firstboot release-gate handoff freshness passed: verified required artifacts are within '
            f'the {max_age_minutes}-minute policy window ({fresh_required}/{required_verified}).'
        )
    return (
        'Firstboot release-gate handoff freshness is deferred; regenerate verification evidence from the current '
        'privacy-safe handoff bundle before ISO promotion, recovery handoff, or manager review.'
    )


def handoff_checklist(ok: bool) -> list[str]:
    if ok:
        return [
            'Attach freshness JSON or Markdown beside the handoff verification artifact during release review.',
            'Confirm the freshness policy matches the promoted ISO, recovery bundle, or handoff archive policy.',
            'Keep raw telemetry, credentials, packet captures, model binaries, datasets, and identities out of the bundle.',
        ]
    return [
        'Review blockers and regenerate the handoff verification artifact from a current firstboot evidence set.',
        'Confirm the reviewer clock and copied artifact mtimes are reasonable before promotion.',
        'Do not treat stale, missing, malformed, or unverified evidence as approval.',
    ]


def render_markdown(freshness: Dict[str, Any]) -> str:
    policy = freshness['freshness_policy']
    counts = freshness['artifact_counts']
    verification = freshness['verification_artifact']
    lines = [
        '# Firstboot release-gate handoff freshness',
        '',
        f"- Decision: `{freshness['decision']}`",
        f"- Release gate: `{freshness['release_gate']}`",
        f"- Created UTC: `{freshness['created_utc']}`",
        f"- Input path: `{freshness['input_path']}`",
        f"- Max artifact age: `{policy['max_age_minutes']}` minutes",
        f"- Privacy scope: `{freshness['privacy_scope']}`",
        '',
        '## Manager summary',
        '',
        freshness['manager_summary'],
        '',
        '## Verification artifact',
        '',
        '| Field | Value |',
        '| --- | --- |',
        f"| exists | `{verification['exists']}` |",
        f"| fresh | `{verification['fresh']}` |",
        f"| mtime_utc | `{verification['mtime_utc'] or 'missing'}` |",
        f"| age_seconds | `{verification['age_seconds'] if verification['age_seconds'] is not None else 'missing'}` |",
        '',
        '## Artifact counts',
        '',
        '| Field | Value |',
        '| --- | --- |',
        f"| total | `{counts['total']}` |",
        f"| required_verified | `{counts['required_verified']}` |",
        f"| fresh_required_verified | `{counts['fresh_required_verified']}` |",
        '',
        '## Artifacts',
        '',
        '| Label | Required | Verified | Exists | Fresh | Age seconds |',
        '| --- | --- | --- | --- | --- | --- |',
    ]
    for artifact in freshness['artifacts']:
        age = artifact['age_seconds'] if artifact['age_seconds'] is not None else 'missing'
        lines.append(
            f"| `{artifact['label']}` | `{artifact['required']}` | `{artifact['verified']}` | "
            f"`{artifact['exists']}` | `{artifact['fresh']}` | `{age}` |"
        )
    lines.extend(['', '## Blockers', ''])
    blockers = freshness.get('blockers', [])
    if blockers:
        lines.extend(f'- `{blocker}`' for blocker in blockers)
    else:
        lines.append('- None')
    lines.extend([
        '',
        '## Handoff checklist',
        '',
        *[f'- {item}' for item in freshness['handoff_checklist']],
        '',
        '## Privacy and safety',
        '',
        f"- Safe default: {freshness['safe_default']}",
        f"- Privacy exclusions: {', '.join(freshness['privacy_exclusions'])}",
        '',
        '## Rollback',
        '',
        freshness['rollback_note'],
        '',
    ])
    return '\n'.join(lines)


def write_output(path: Path, freshness: Dict[str, Any], output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == 'markdown':
        path.write_text(render_markdown(freshness), encoding='utf-8')
        return
    path.write_text(json.dumps(freshness, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Check passive firstboot release-gate handoff verification freshness.')
    parser.add_argument('--input', default=str(DEFAULT_INPUT), help='Path to firstboot release-gate handoff verification JSON.')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--max-artifact-age-minutes', type=int, default=DEFAULT_MAX_AGE_MINUTES)
    parser.add_argument('--require-fresh', action='store_true', help='Exit non-zero unless verified evidence is fresh.')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    freshness = build_freshness(Path(args.input), args.max_artifact_age_minutes)
    write_output(Path(args.output), freshness, args.format)
    print(json.dumps({'decision': freshness['decision'], 'format': args.format, 'ok': freshness['ok'], 'output': args.output}, sort_keys=True))
    return 0 if freshness['ok'] or not args.require_fresh else 10


if __name__ == '__main__':
    sys.exit(main())
