#!/usr/bin/env python3
# MINC - Defensive firstboot release-gate handoff index builder.
# Purpose: index privacy-safe aggregate release-gate artifacts for operator handoff.

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_OUTPUT = Path('/var/log/firstboot_release_gate.handoff_index.json')

DEFAULT_ARTIFACTS = {
    'release_gate_json': {
        'path': Path('/var/log/firstboot_release_gate.json'),
        'required': False,
        'component': 'firstboot_release_gate',
        'format': 'json',
    },
    'release_gate_markdown': {
        'path': Path('/var/log/firstboot_release_gate.md'),
        'required': False,
        'format': 'markdown',
    },
    'summary_env': {
        'path': Path('/var/log/firstboot_release_gate.summary.env'),
        'required': False,
        'format': 'env',
    },
    'status_json': {
        'path': Path('/var/log/firstboot_release_gate.status.json'),
        'required': True,
        'component': 'firstboot_release_gate_status',
        'format': 'json',
    },
    'bundle_manifest_json': {
        'path': Path('/var/log/firstboot_release_gate.bundle_manifest.json'),
        'required': True,
        'component': 'firstboot_release_gate_bundle_manifest',
        'format': 'json',
    },
    'bundle_manifest_markdown': {
        'path': Path('/var/log/firstboot_release_gate.bundle_manifest.md'),
        'required': False,
        'format': 'markdown',
    },
    'operator_digest_json': {
        'path': Path('/var/log/firstboot_release_gate.operator_digest.json'),
        'required': True,
        'component': 'firstboot_release_gate_operator_digest',
        'format': 'json',
    },
    'operator_digest_markdown': {
        'path': Path('/var/log/firstboot_release_gate.operator_digest.md'),
        'required': False,
        'format': 'markdown',
    },
}

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


def read_json_object(path: Path, label: str) -> tuple[Dict[str, Any], list[str]]:
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        return {}, [f'invalid_json:{label}:{exc.msg}']
    if not isinstance(payload, dict):
        return {}, [f'invalid_json:{label}:top-level JSON must be an object']
    return payload, []


def artifact_record(label: str, spec: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any], list[str]]:
    path = Path(spec['path'])
    required = bool(spec.get('required'))
    record: Dict[str, Any] = {
        'label': label,
        'path': str(path),
        'required': required,
        'format': spec.get('format', 'unknown'),
        'exists': path.exists() and path.is_file(),
    }
    payload: Dict[str, Any] = {}
    blockers: list[str] = []
    if not record['exists']:
        record.update({'size_bytes': 0, 'sha256': None})
        if required:
            blockers.append(f'missing_required_artifact:{label}')
        return record, payload, blockers

    record['size_bytes'] = path.stat().st_size
    record['sha256'] = sha256_file(path)
    if spec.get('format') == 'json':
        payload, json_errors = read_json_object(path, label)
        blockers.extend(json_errors)
        expected_component = spec.get('component')
        if expected_component and payload and payload.get('component') != expected_component:
            blockers.append(f'component_mismatch:{label}:{payload.get("component", "unknown")}')
        record['component'] = payload.get('component', expected_component or 'unknown') if payload else spec.get('component')
        record['decision'] = payload.get('decision') if payload else None
        record['release_gate'] = payload.get('release_gate') if payload else None
        record['ok'] = payload.get('ok') if payload else None
    return record, payload, blockers


def build_index(artifacts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    records = []
    payloads: Dict[str, Dict[str, Any]] = {}
    blockers: list[str] = []
    for label, spec in artifacts.items():
        record, payload, artifact_blockers = artifact_record(label, spec)
        records.append(record)
        if payload:
            payloads[label] = payload
        blockers.extend(artifact_blockers)

    json_decisions = {
        label: payload.get('decision')
        for label, payload in payloads.items()
        if payload.get('decision') is not None
    }
    json_gates = {
        label: payload.get('release_gate')
        for label, payload in payloads.items()
        if payload.get('release_gate') is not None
    }
    if len(set(json_decisions.values())) > 1:
        blockers.append('decision_mismatch_across_handoff_artifacts')
    if len(set(json_gates.values())) > 1:
        blockers.append('release_gate_mismatch_across_handoff_artifacts')

    for label in ('status_json', 'bundle_manifest_json', 'operator_digest_json'):
        payload = payloads.get(label, {})
        if payload and payload.get('ok') is not True:
            blockers.append(f'{label}_not_passing')
        if payload and payload.get('release_gate') != 'pass':
            blockers.append(f'{label}_release_gate:{payload.get("release_gate", "unknown")}')

    required_total = sum(1 for record in records if record['required'])
    required_present = sum(1 for record in records if record['required'] and record['exists'])
    markdown_present = sum(1 for record in records if record['format'] == 'markdown' and record['exists'])
    ok = not blockers
    return {
        'schema_version': 1,
        'component': 'firstboot_release_gate_handoff_index',
        'created_utc': utc_now(),
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'artifact_counts': {
            'total': len(records),
            'required': required_total,
            'required_present': required_present,
            'markdown_present': markdown_present,
            'hashed': sum(1 for record in records if record.get('sha256')),
        },
        'artifacts': records,
        'blockers': sorted(set(blockers)),
        'manager_summary': manager_summary(ok, required_present, required_total, markdown_present),
        'handoff_checklist': handoff_checklist(ok),
        'privacy_scope': 'aggregate_release_gate_handoff_index_only',
        'privacy_exclusions': list(PRIVACY_EXCLUDED),
        'safe_default': (
            'read-only handoff index; no host, VM, firewall, service, model, dataset, approval, restore, '
            'network, or firstboot state was changed'
        ),
        'rollback_note': (
            'delete the generated handoff index artifacts or revert this additive helper, docs, tests, packaging entry, '
            'and service post-step; upstream release-gate evidence remains unchanged'
        ),
    }


def manager_summary(ok: bool, required_present: int, required_total: int, markdown_present: int) -> str:
    if ok:
        return (
            'Firstboot release-gate handoff artifacts are present, internally consistent, hashed, and ready '
            f'for review with {required_present}/{required_total} required artifacts and {markdown_present} Markdown summaries.'
        )
    return (
        'Firstboot release-gate handoff is deferred; regenerate missing or inconsistent aggregate artifacts '
        'before ISO promotion, firstboot handoff, or recovery bundle review.'
    )


def handoff_checklist(ok: bool) -> list[str]:
    if ok:
        return [
            'Attach the handoff index, status JSON, bundle manifest JSON/Markdown, and operator digest JSON/Markdown to release review.',
            'Verify SHA-256 values against the promoted ISO, recovery bundle, or handoff archive.',
            'Confirm no raw telemetry, identities, credentials, model binaries, or datasets are included in the handoff bundle.',
        ]
    return [
        'Regenerate firstboot release-gate status, bundle manifest, and operator digest artifacts from the same run.',
        'Review blockers in this index before promotion or recovery handoff.',
        'Do not treat missing or mismatched evidence as approval.',
    ]


def render_markdown(index: Dict[str, Any]) -> str:
    counts = index['artifact_counts']
    lines = [
        '# Firstboot release-gate handoff index',
        '',
        f"- Decision: `{index['decision']}`",
        f"- Release gate: `{index['release_gate']}`",
        f"- Created UTC: `{index['created_utc']}`",
        f"- Privacy scope: `{index['privacy_scope']}`",
        '',
        '## Manager summary',
        '',
        index['manager_summary'],
        '',
        '## Artifact counts',
        '',
        '| Field | Value |',
        '| --- | --- |',
        f"| total | `{counts['total']}` |",
        f"| required | `{counts['required']}` |",
        f"| required_present | `{counts['required_present']}` |",
        f"| markdown_present | `{counts['markdown_present']}` |",
        f"| hashed | `{counts['hashed']}` |",
        '',
        '## Artifacts',
        '',
        '| Label | Required | Exists | Format | SHA-256 |',
        '| --- | --- | --- | --- | --- |',
    ]
    for artifact in index['artifacts']:
        sha = artifact.get('sha256') or 'missing'
        lines.append(
            f"| `{artifact['label']}` | `{artifact['required']}` | `{artifact['exists']}` | "
            f"`{artifact['format']}` | `{sha}` |"
        )
    lines.extend(['', '## Blockers', ''])
    blockers = index.get('blockers', [])
    if blockers:
        lines.extend(f'- `{blocker}`' for blocker in blockers)
    else:
        lines.append('- None')
    lines.extend([
        '',
        '## Handoff checklist',
        '',
        *[f'- {item}' for item in index['handoff_checklist']],
        '',
        '## Privacy and safety',
        '',
        f"- Safe default: {index['safe_default']}",
        f"- Privacy exclusions: {', '.join(index['privacy_exclusions'])}",
        '',
        '## Rollback',
        '',
        index['rollback_note'],
        '',
    ])
    return '\n'.join(lines)


def write_index(path: Path, index: Dict[str, Any], output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == 'markdown':
        path.write_text(render_markdown(index), encoding='utf-8')
        return
    path.write_text(json.dumps(index, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a passive firstboot release-gate handoff index.')
    for label, spec in DEFAULT_ARTIFACTS.items():
        parser.add_argument(f'--{label.replace("_", "-")}', default=str(spec['path']))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--require-ready', action='store_true', help='Exit non-zero unless the index is approved.')
    return parser.parse_args(argv)


def artifact_specs_from_args(args: argparse.Namespace) -> Dict[str, Dict[str, Any]]:
    specs: Dict[str, Dict[str, Any]] = {}
    for label, spec in DEFAULT_ARTIFACTS.items():
        arg_name = label
        specs[label] = dict(spec)
        specs[label]['path'] = Path(getattr(args, arg_name))
    return specs


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    index = build_index(artifact_specs_from_args(args))
    write_index(Path(args.output), index, args.format)
    print(json.dumps({'decision': index['decision'], 'format': args.format, 'ok': index['ok'], 'output': args.output}, sort_keys=True))
    return 0 if index['ok'] or not args.require_ready else 8


if __name__ == '__main__':
    sys.exit(main())
