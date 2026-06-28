#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate operator digest builder.
# Purpose: summarize aggregate release-gate evidence for handoff without reading raw telemetry.

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_STATUS_JSON = Path('/var/log/firstboot_release_gate.status.json')
DEFAULT_BUNDLE_JSON = Path('/var/log/firstboot_release_gate.bundle_manifest.json')
DEFAULT_OUTPUT = Path('/var/log/firstboot_release_gate.operator_digest.json')

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


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def load_json_object(path: Path, label: str) -> tuple[Dict[str, Any], list[str]]:
    if not path.exists() or not path.is_file():
        return {}, [f'missing_{label}:{path}']
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        return {}, [f'invalid_{label}_json:{path}:{exc.msg}']
    if not isinstance(payload, dict):
        return {}, [f'invalid_{label}_json:{path}:top-level JSON must be an object']
    return payload, []


def artifact_counts(bundle: Dict[str, Any]) -> Dict[str, int]:
    artifacts = bundle.get('artifacts', [])
    if not isinstance(artifacts, list):
        return {'total': 0, 'required': 0, 'present': 0, 'missing_required': 0, 'hashed': 0}
    total = required = present = missing_required = hashed = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        total += 1
        is_required = artifact.get('required') is True
        exists = artifact.get('exists') is True
        if is_required:
            required += 1
        if exists:
            present += 1
        if is_required and not exists:
            missing_required += 1
        if artifact.get('sha256'):
            hashed += 1
    return {
        'total': total,
        'required': required,
        'present': present,
        'missing_required': missing_required,
        'hashed': hashed,
    }


def digest_blockers(status: Dict[str, Any], bundle: Dict[str, Any], load_errors: list[str]) -> list[str]:
    blockers = list(load_errors)
    if status and status.get('component') != 'firstboot_release_gate_status':
        blockers.append('status_component_mismatch')
    if bundle and bundle.get('component') != 'firstboot_release_gate_bundle_manifest':
        blockers.append('bundle_component_mismatch')
    if status and status.get('ok') is not True:
        blockers.append('status_not_passing')
    if bundle and bundle.get('ok') is not True:
        blockers.append('bundle_not_passing')
    if status and status.get('release_gate') != 'pass':
        blockers.append(f"status_release_gate:{status.get('release_gate', 'unknown')}")
    if bundle and bundle.get('release_gate') != 'pass':
        blockers.append(f"bundle_release_gate:{bundle.get('release_gate', 'unknown')}")
    if status and bundle and status.get('decision') != bundle.get('decision'):
        blockers.append('decision_mismatch_between_status_and_bundle')
    if status and bundle and status.get('release_gate') != bundle.get('release_gate'):
        blockers.append('release_gate_mismatch_between_status_and_bundle')
    if status.get('validation_blockers'):
        blockers.append('status_validation_blockers_present')
    if bundle.get('blockers'):
        blockers.append('bundle_blockers_present')
    counts = artifact_counts(bundle)
    if counts['missing_required']:
        blockers.append('bundle_missing_required_artifacts')
    if counts['required'] and counts['hashed'] < counts['required']:
        blockers.append('bundle_required_artifacts_without_hashes')
    return sorted(set(blockers))


def build_digest(status_path: Path, bundle_path: Path) -> Dict[str, Any]:
    status, status_errors = load_json_object(status_path, 'status')
    bundle, bundle_errors = load_json_object(bundle_path, 'bundle')
    blockers = digest_blockers(status, bundle, status_errors + bundle_errors)
    counts = artifact_counts(bundle)
    ok = not blockers
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_operator_digest',
        'created_utc': utc_now(),
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'source_paths': {
            'status_json': str(status_path),
            'bundle_manifest_json': str(bundle_path),
        },
        'source_summary': {
            'status_decision': status.get('decision', 'unknown'),
            'status_release_gate': status.get('release_gate', 'unknown'),
            'status_created_utc': status.get('source_created_utc', 'unknown'),
            'bundle_decision': bundle.get('decision', 'unknown'),
            'bundle_release_gate': bundle.get('release_gate', 'unknown'),
            'bundle_created_utc': bundle.get('created_utc', 'unknown'),
            'status_blocker_count': status.get('blocker_count', 0),
            'status_stale_or_skewed_count': status.get('stale_or_skewed_count', 0),
            'bundle_artifact_counts': counts,
        },
        'blockers': blockers,
        'manager_summary': manager_summary(ok, blockers, counts),
        'handoff_checklist': handoff_checklist(ok, blockers, counts),
        'privacy_scope': 'aggregate_release_gate_evidence_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': (
            'read-only operator digest; no host, VM, firewall, service, model, dataset, approval, restore, '
            'network, or firstboot state was changed'
        ),
        'rollback_note': (
            'delete the generated operator digest or revert this additive helper, docs, tests, packaging entry, '
            'and service post-step; upstream release-gate artifacts remain unchanged'
        ),
    }


def manager_summary(ok: bool, blockers: list[str], counts: Dict[str, int]) -> str:
    if ok:
        return (
            'Firstboot release-gate evidence is internally consistent, passing, privacy-scoped, and ready for '
            f"operator review with {counts['present']} referenced artifacts and {counts['hashed']} hashes."
        )
    return (
        'Firstboot release-gate evidence is deferred; review the listed blockers and regenerate aggregate '
        'status or bundle artifacts before promotion.'
    )


def handoff_checklist(ok: bool, blockers: list[str], counts: Dict[str, int]) -> list[str]:
    if ok:
        return [
            'Attach status JSON, bundle manifest JSON, bundle manifest Markdown, and this operator digest to release review.',
            'Verify SHA-256 values match the promoted ISO or recovery bundle artifacts.',
            'Confirm no raw telemetry, identities, credentials, model binaries, or datasets are included in handoff artifacts.',
        ]
    actions = []
    if any(blocker.startswith('missing_') or blocker.startswith('invalid_') for blocker in blockers):
        actions.append('Regenerate missing or malformed aggregate release-gate artifacts before relying on the digest.')
    if 'decision_mismatch_between_status_and_bundle' in blockers or 'release_gate_mismatch_between_status_and_bundle' in blockers:
        actions.append('Refresh status and bundle artifacts from the same firstboot release-gate run before promotion.')
    if 'bundle_missing_required_artifacts' in blockers or counts['missing_required']:
        actions.append('Regenerate the complete release-gate evidence bundle so all required artifacts are present.')
    if 'bundle_required_artifacts_without_hashes' in blockers:
        actions.append('Regenerate the bundle manifest so every required artifact has a SHA-256 reference.')
    if not actions:
        actions.append('Review release-gate blockers and defer promotion until status and bundle evidence both pass.')
    return sorted(set(actions))


def render_markdown(digest: Dict[str, Any]) -> str:
    counts = digest['source_summary']['bundle_artifact_counts']
    lines = [
        '# Firstboot release-gate operator digest',
        '',
        f"- Decision: `{digest['decision']}`",
        f"- Release gate: `{digest['release_gate']}`",
        f"- Created UTC: `{digest['created_utc']}`",
        f"- Privacy scope: `{digest['privacy_scope']}`",
        '',
        '## Manager summary',
        '',
        digest['manager_summary'],
        '',
        '## Source summary',
        '',
        '| Field | Value |',
        '| --- | --- |',
    ]
    for key, value in digest['source_summary'].items():
        if key == 'bundle_artifact_counts':
            continue
        lines.append(f'| {key} | `{value}` |')
    lines.extend([
        f"| bundle_artifacts_total | `{counts['total']}` |",
        f"| bundle_artifacts_required | `{counts['required']}` |",
        f"| bundle_artifacts_present | `{counts['present']}` |",
        f"| bundle_artifacts_missing_required | `{counts['missing_required']}` |",
        f"| bundle_artifacts_hashed | `{counts['hashed']}` |",
        '',
        '## Blockers',
        '',
    ])
    blockers = digest.get('blockers', [])
    if blockers:
        lines.extend(f'- `{blocker}`' for blocker in blockers)
    else:
        lines.append('- None')
    lines.extend(['', '## Handoff checklist', ''])
    lines.extend(f'- {item}' for item in digest.get('handoff_checklist', []))
    lines.extend([
        '',
        '## Privacy and safety',
        '',
        f"- Safe default: {digest['safe_default']}",
        f"- Privacy exclusions: {', '.join(digest['privacy_exclusions'])}",
        '',
        '## Rollback',
        '',
        digest['rollback_note'],
        '',
    ])
    return '\n'.join(lines)


def write_digest(path: Path, digest: Dict[str, Any], output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == 'markdown':
        path.write_text(render_markdown(digest), encoding='utf-8')
        return
    path.write_text(json.dumps(digest, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a passive firstboot release-gate operator digest.')
    parser.add_argument('--status-json', default=str(DEFAULT_STATUS_JSON))
    parser.add_argument('--bundle-json', default=str(DEFAULT_BUNDLE_JSON))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--require-pass', action='store_true', help='Exit non-zero unless the digest is passing.')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    digest = build_digest(Path(args.status_json), Path(args.bundle_json))
    write_digest(Path(args.output), digest, args.format)
    print(json.dumps({'decision': digest['decision'], 'format': args.format, 'ok': digest['ok'], 'output': args.output}, sort_keys=True))
    return 0 if digest['ok'] or not args.require_pass else 7


if __name__ == '__main__':
    sys.exit(main())
