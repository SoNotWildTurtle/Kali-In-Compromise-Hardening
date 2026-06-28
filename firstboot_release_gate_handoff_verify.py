#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate handoff verification helper.
# Purpose: verify privacy-safe handoff indexes and artifact hashes before promotion.

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

DEFAULT_INDEX = Path('/var/log/firstboot_release_gate.handoff_index.json')
DEFAULT_OUTPUT = Path('/var/log/firstboot_release_gate.handoff_verify.json')

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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_object(path: Path) -> tuple[Dict[str, Any], list[str]]:
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}, [f'missing_index:{path}']
    except json.JSONDecodeError as exc:
        return {}, [f'invalid_index_json:{exc.msg}']
    if not isinstance(payload, dict):
        return {}, ['invalid_index_json:top-level JSON must be an object']
    return payload, []


def artifact_path(index_path: Path, artifact: Dict[str, Any], artifact_root: Optional[Path]) -> Path:
    recorded = Path(str(artifact.get('path', '')))
    if artifact_root:
        return artifact_root / recorded.name
    if recorded.exists():
        return recorded
    return index_path.parent / recorded.name


def verify_artifact(index_path: Path, artifact: Dict[str, Any], artifact_root: Optional[Path]) -> tuple[Dict[str, Any], list[str]]:
    label = str(artifact.get('label', 'unknown'))
    expected_sha = artifact.get('sha256')
    required = bool(artifact.get('required'))
    expected_exists = bool(artifact.get('exists'))
    expected_size = artifact.get('size_bytes')
    path = artifact_path(index_path, artifact, artifact_root)
    exists = path.exists() and path.is_file()
    record: Dict[str, Any] = {
        'label': label,
        'path': str(path),
        'required': required,
        'expected_exists': expected_exists,
        'exists': exists,
        'expected_size_bytes': expected_size,
        'size_bytes': path.stat().st_size if exists else 0,
        'expected_sha256': expected_sha,
        'sha256': sha256_file(path) if exists else None,
        'verified': False,
    }
    blockers: list[str] = []

    if required and not exists:
        blockers.append(f'missing_required_artifact:{label}')
    if expected_exists and not exists:
        blockers.append(f'missing_indexed_artifact:{label}')
    if exists and expected_size is not None and record['size_bytes'] != expected_size:
        blockers.append(f'size_mismatch:{label}')
    if exists and expected_sha and record['sha256'] != expected_sha:
        blockers.append(f'sha256_mismatch:{label}')
    if exists and not expected_sha:
        blockers.append(f'missing_expected_sha256:{label}')
    label_blocked = any(blocker.endswith(f':{label}') for blocker in blockers)
    record['verified'] = exists and not label_blocked
    return record, blockers


def normalize_blockers(blockers: Iterable[str]) -> list[str]:
    return sorted(set(str(blocker) for blocker in blockers if str(blocker)))


def build_verification(index_path: Path, artifact_root: Optional[Path] = None) -> Dict[str, Any]:
    index, index_blockers = read_json_object(index_path)
    records = []
    blockers = list(index_blockers)

    if index and index.get('component') != 'firstboot_release_gate_handoff_index':
        blockers.append(f'component_mismatch:{index.get("component", "unknown")}')
    if index and index.get('privacy_scope') != 'aggregate_release_gate_handoff_index_only':
        blockers.append(f'privacy_scope_mismatch:{index.get("privacy_scope", "unknown")}')
    if index and index.get('ok') is not True:
        blockers.append('handoff_index_not_approved')
    if index and index.get('release_gate') != 'pass':
        blockers.append(f'handoff_index_release_gate:{index.get("release_gate", "unknown")}')

    artifacts = index.get('artifacts', []) if index else []
    if index and not isinstance(artifacts, list):
        blockers.append('invalid_artifacts:must_be_list')
        artifacts = []

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            blockers.append('invalid_artifact_record:must_be_object')
            continue
        record, artifact_blockers = verify_artifact(index_path, artifact, artifact_root)
        records.append(record)
        blockers.extend(artifact_blockers)

    required_total = sum(1 for record in records if record['required'])
    required_verified = sum(1 for record in records if record['required'] and record['verified'])
    hashed_total = sum(1 for record in records if record.get('expected_sha256'))
    hashed_verified = sum(1 for record in records if record.get('expected_sha256') and record['verified'])
    blockers = normalize_blockers(blockers)
    ok = not blockers
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_handoff_verify',
        'created_utc': utc_now(),
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'index_path': str(index_path),
        'artifact_root': str(artifact_root) if artifact_root else None,
        'artifact_counts': {
            'total': len(records),
            'required': required_total,
            'required_verified': required_verified,
            'hashed': hashed_total,
            'hashed_verified': hashed_verified,
        },
        'artifacts': records,
        'blockers': blockers,
        'manager_summary': manager_summary(ok, required_verified, required_total, hashed_verified, hashed_total),
        'handoff_checklist': handoff_checklist(ok),
        'privacy_scope': 'aggregate_release_gate_handoff_verification_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': (
            'read-only verifier; no host, VM, firewall, service, model, dataset, approval, restore, '
            'network, or firstboot state was changed'
        ),
        'rollback_note': (
            'delete the generated verification artifact or revert this additive helper, docs, tests, and packaging entry; '
            'handoff index and upstream release-gate evidence remain unchanged'
        ),
    }


def manager_summary(ok: bool, required_verified: int, required_total: int, hashed_verified: int, hashed_total: int) -> str:
    if ok:
        return (
            'Firstboot release-gate handoff verification passed: required artifacts are present and indexed '
            f'hashes match ({required_verified}/{required_total} required, {hashed_verified}/{hashed_total} hashed).'
        )
    return (
        'Firstboot release-gate handoff verification is deferred; regenerate or recopy the privacy-safe handoff bundle '
        'before ISO promotion, recovery handoff, or manager review.'
    )


def handoff_checklist(ok: bool) -> list[str]:
    if ok:
        return [
            'Attach verification JSON with the handoff index and aggregate artifacts during release review.',
            'Confirm the artifact root matches the promoted ISO, recovery bundle, or handoff archive under review.',
            'Keep raw telemetry, credentials, packet captures, model binaries, datasets, and identities out of the bundle.',
        ]
    return [
        'Review blockers and compare SHA-256 values against the handoff index.',
        'Regenerate firstboot release-gate status, bundle manifest, operator digest, and handoff index from one run.',
        'Do not treat missing, mismatched, or unverified evidence as approval.',
    ]


def render_markdown(verification: Dict[str, Any]) -> str:
    counts = verification['artifact_counts']
    lines = [
        '# Firstboot release-gate handoff verification',
        '',
        f"- Decision: `{verification['decision']}`",
        f"- Release gate: `{verification['release_gate']}`",
        f"- Created UTC: `{verification['created_utc']}`",
        f"- Index path: `{verification['index_path']}`",
        f"- Artifact root: `{verification['artifact_root'] or 'recorded paths or index directory'}`",
        f"- Privacy scope: `{verification['privacy_scope']}`",
        '',
        '## Manager summary',
        '',
        verification['manager_summary'],
        '',
        '## Artifact counts',
        '',
        '| Field | Value |',
        '| --- | --- |',
        f"| total | `{counts['total']}` |",
        f"| required | `{counts['required']}` |",
        f"| required_verified | `{counts['required_verified']}` |",
        f"| hashed | `{counts['hashed']}` |",
        f"| hashed_verified | `{counts['hashed_verified']}` |",
        '',
        '## Artifacts',
        '',
        '| Label | Required | Exists | Verified | SHA-256 |',
        '| --- | --- | --- | --- | --- |',
    ]
    for artifact in verification['artifacts']:
        sha = artifact.get('sha256') or 'missing'
        lines.append(
            f"| `{artifact['label']}` | `{artifact['required']}` | `{artifact['exists']}` | "
            f"`{artifact['verified']}` | `{sha}` |"
        )
    lines.extend(['', '## Blockers', ''])
    blockers = verification.get('blockers', [])
    if blockers:
        lines.extend(f'- `{blocker}`' for blocker in blockers)
    else:
        lines.append('- None')
    lines.extend([
        '',
        '## Handoff checklist',
        '',
        *[f'- {item}' for item in verification['handoff_checklist']],
        '',
        '## Privacy and safety',
        '',
        f"- Safe default: {verification['safe_default']}",
        f"- Privacy exclusions: {', '.join(verification['privacy_exclusions'])}",
        '',
        '## Rollback',
        '',
        verification['rollback_note'],
        '',
    ])
    return '\n'.join(lines)


def write_output(path: Path, verification: Dict[str, Any], output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == 'markdown':
        path.write_text(render_markdown(verification), encoding='utf-8')
        return
    path.write_text(json.dumps(verification, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Verify a passive firstboot release-gate handoff index and artifact hashes.')
    parser.add_argument('--index', default=str(DEFAULT_INDEX), help='Path to firstboot release-gate handoff index JSON.')
    parser.add_argument('--artifact-root', default=None, help='Directory containing copied handoff artifacts; defaults to recorded paths or the index directory.')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--require-verified', action='store_true', help='Exit non-zero unless all indexed evidence verifies.')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    artifact_root = Path(args.artifact_root) if args.artifact_root else None
    verification = build_verification(Path(args.index), artifact_root)
    write_output(Path(args.output), verification, args.format)
    print(json.dumps({'decision': verification['decision'], 'format': args.format, 'ok': verification['ok'], 'output': args.output}, sort_keys=True))
    return 0 if verification['ok'] or not args.require_verified else 9


if __name__ == '__main__':
    sys.exit(main())
