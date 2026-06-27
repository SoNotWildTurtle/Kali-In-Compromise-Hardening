#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate bundle manifest builder.
# Purpose: record privacy-safe release-gate evidence references without changing host or VM state.

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_GATE_JSON = Path('/var/log/firstboot_release_gate.json')
DEFAULT_GATE_MARKDOWN = Path('/var/log/firstboot_release_gate.md')
DEFAULT_GATE_SUMMARY = Path('/var/log/firstboot_release_gate.summary.env')
DEFAULT_STATUS_JSON = Path('/var/log/firstboot_release_gate.status.json')
DEFAULT_OUTPUT = Path('/var/log/firstboot_release_gate.bundle_manifest.json')

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


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_record(name: str, path: Path, required: bool) -> Dict[str, Any]:
    exists = path.exists() and path.is_file()
    record: Dict[str, Any] = {
        'name': name,
        'path': str(path),
        'required': required,
        'exists': exists,
        'sha256': sha256_file(path),
    }
    if exists:
        stat = path.stat()
        record['size_bytes'] = stat.st_size
    return record


def load_status(path: Path) -> tuple[Dict[str, Any], list[str]]:
    if not path.exists() or not path.is_file():
        return {}, [f'missing_status:{path}']
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        return {}, [f'invalid_status_json:{path}:{exc.msg}']
    if not isinstance(payload, dict):
        return {}, [f'invalid_status_json:{path}:top-level JSON must be an object']
    return payload, []


def manifest_blockers(artifacts: list[Dict[str, Any]], status: Dict[str, Any], status_errors: list[str]) -> list[str]:
    blockers = list(status_errors)
    blockers.extend(
        f"missing_required_artifact:{artifact['name']}"
        for artifact in artifacts
        if artifact['required'] and not artifact['exists']
    )
    if status and status.get('component') != 'firstboot_release_gate_status':
        blockers.append('status_component_mismatch')
    if status and status.get('ok') is not True:
        blockers.append('status_not_passing')
    if status and status.get('release_gate') != 'pass':
        blockers.append(f"status_release_gate:{status.get('release_gate', 'unknown')}")
    validation_blockers = status.get('validation_blockers') if isinstance(status, dict) else None
    if validation_blockers:
        blockers.append('status_validation_blockers_present')
    return sorted(set(blockers))


def build_manifest(args: argparse.Namespace) -> Dict[str, Any]:
    artifacts = [
        artifact_record('firstboot_release_gate_json', Path(args.gate_json), True),
        artifact_record('firstboot_release_gate_markdown', Path(args.gate_markdown), True),
        artifact_record('firstboot_release_gate_summary', Path(args.summary), True),
        artifact_record('firstboot_release_gate_status_json', Path(args.status_json), True),
    ]
    status_payload, status_errors = load_status(Path(args.status_json))
    blockers = manifest_blockers(artifacts, status_payload, status_errors)
    ok = not blockers
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_bundle_manifest',
        'created_utc': utc_now(),
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'artifacts': artifacts,
        'status_summary': {
            'component': status_payload.get('component', 'unknown'),
            'decision': status_payload.get('decision', 'unknown'),
            'release_gate': status_payload.get('release_gate', 'unknown'),
            'source_created_utc': status_payload.get('source_created_utc', 'unknown'),
            'artifact_count': status_payload.get('artifact_count', 0),
            'blocker_count': status_payload.get('blocker_count', 0),
            'stale_or_skewed_count': status_payload.get('stale_or_skewed_count', 0),
        },
        'blockers': blockers,
        'privacy_scope': 'aggregate_references_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': (
            'read-only manifest builder; no host, VM, firewall, service, model, dataset, approval, restore, '
            'or firstboot state was changed'
        ),
        'rollback_note': (
            'delete the generated bundle manifest or revert this additive helper, docs, tests, and packaging entry; '
            'upstream release-gate artifacts remain unchanged'
        ),
        'operator_next_steps': operator_next_steps(blockers),
    }


def operator_next_steps(blockers: list[str]) -> list[str]:
    if not blockers:
        return [
            'Attach the bundle manifest with the JSON, Markdown, summary, and status artifacts for release review.',
            'Verify artifact SHA-256 values match the files promoted with the ISO or recovery bundle.',
        ]
    actions = []
    if any(blocker.startswith('missing_required_artifact:') for blocker in blockers):
        actions.append('Regenerate all firstboot release-gate artifacts before creating the bundle manifest.')
    if any(blocker.startswith('missing_status:') or blocker.startswith('invalid_status_json:') for blocker in blockers):
        actions.append('Regenerate firstboot_release_gate_status.py JSON output before relying on bundle evidence.')
    if any(blocker.startswith('status_') for blocker in blockers):
        actions.append('Review firstboot release-gate status blockers before promotion.')
    return sorted(set(actions))


def write_manifest(path: Path, manifest: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a passive firstboot release-gate evidence bundle manifest.')
    parser.add_argument('--gate-json', default=str(DEFAULT_GATE_JSON))
    parser.add_argument('--gate-markdown', default=str(DEFAULT_GATE_MARKDOWN))
    parser.add_argument('--summary', default=str(DEFAULT_GATE_SUMMARY))
    parser.add_argument('--status-json', default=str(DEFAULT_STATUS_JSON))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument(
        '--require-pass',
        action='store_true',
        help='Exit non-zero unless the manifest references complete passing evidence.',
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    manifest = build_manifest(args)
    write_manifest(Path(args.output), manifest)
    print(json.dumps({'decision': manifest['decision'], 'ok': manifest['ok'], 'output': args.output}, sort_keys=True))
    return 0 if manifest['ok'] or not args.require_pass else 7


if __name__ == '__main__':
    sys.exit(main())
