#!/usr/bin/env python3
# MINC - Defensive host/VM firstboot handoff manifest generator.
# Purpose: verify privacy-safe firstboot handoff artifacts without reading raw telemetry.

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_BUNDLE = Path('/var/lib/host_vm_comm_guard/policy_evidence_bundle.json')
DEFAULT_BUNDLE_REPORT = Path('/var/log/host_vm_policy_evidence_bundle.report')
DEFAULT_RECEIPT = Path('/var/lib/host_vm_comm_guard/policy_evidence_bundle_receipt.json')
DEFAULT_RECEIPT_MARKDOWN = Path('/var/log/host_vm_policy_evidence_bundle_receipt.md')
DEFAULT_HANDOFF_INDEX = Path('/var/log/host_vm_policy_firstboot_handoff.json')
DEFAULT_HANDOFF_MARKDOWN = Path('/var/log/host_vm_policy_firstboot_handoff.md')
DEFAULT_MANIFEST = Path('/var/log/host_vm_policy_firstboot_manifest.json')
DEFAULT_MARKDOWN = Path('/var/log/host_vm_policy_firstboot_manifest.md')


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


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        return {'_parse_error': 'invalid_json'}
    return data if isinstance(data, dict) else {'_parse_error': 'json_root_not_object'}


def artifact_entry(name: str, path: Path, required: bool) -> Dict[str, Any]:
    exists = path.exists() and path.is_file()
    entry: Dict[str, Any] = {
        'name': name,
        'path': str(path),
        'required': required,
        'exists': exists,
        'sha256': sha256_file(path),
    }
    if exists:
        entry['size_bytes'] = path.stat().st_size
    return entry


def missing_required(artifacts: Iterable[Dict[str, Any]]) -> List[str]:
    return [artifact['name'] for artifact in artifacts if artifact['required'] and not artifact['exists']]


def build_manifest(args: argparse.Namespace) -> Dict[str, Any]:
    index_path = Path(args.handoff_index)
    receipt_path = Path(args.receipt)
    bundle_path = Path(args.bundle)
    index = load_json(index_path)
    receipt = load_json(receipt_path)
    bundle = load_json(bundle_path)

    artifacts = [
        artifact_entry('policy_evidence_bundle_json', bundle_path, True),
        artifact_entry('policy_evidence_bundle_report', Path(args.bundle_report), True),
        artifact_entry('policy_evidence_bundle_receipt_json', receipt_path, True),
        artifact_entry('policy_evidence_bundle_receipt_markdown', Path(args.receipt_markdown), True),
        artifact_entry('firstboot_handoff_index_json', index_path, True),
        artifact_entry('firstboot_handoff_markdown', Path(args.handoff_markdown), True),
    ]
    missing = missing_required(artifacts)
    parse_errors = [
        name
        for name, doc in (
            ('policy_evidence_bundle_json', bundle),
            ('policy_evidence_bundle_receipt_json', receipt),
            ('firstboot_handoff_index_json', index),
        )
        if doc.get('_parse_error')
    ]
    handoff_ok = bool(index.get('ok', False))
    receipt_ok = bool(receipt.get('ok', False))
    bundle_status = str(index.get('bundle_status') or receipt.get('bundle_status') or bundle.get('overall_status') or 'unknown')
    blockers = list(missing) + [f'{name}:invalid_json' for name in parse_errors]
    if not handoff_ok:
        blockers.append('firstboot_handoff_not_ready')
    if not receipt_ok:
        blockers.append('receipt_not_ready')

    ok = not blockers
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'component': 'host_vm_policy_firstboot_manifest',
        'ok': ok,
        'decision': 'approved' if ok else 'deferred',
        'release_gate': 'pass' if ok else 'stop',
        'bundle_status': bundle_status,
        'handoff_decision': index.get('decision', 'unknown'),
        'receipt_decision': receipt.get('decision', 'unknown'),
        'blockers': blockers,
        'artifacts': artifacts,
        'safe_default': 'read-only manifest; no host, VM, firewall, service, model, dataset, approval, restore, or firstboot state was changed',
        'privacy_note': 'records artifact paths, sizes, SHA-256 digests, decisions, and aggregate status only; raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, and datasets are not embedded',
        'rollback_note': 'delete the generated manifest artifacts or revert this additive helper, packaging entry, docs, and tests; existing handoff, receipt, and evidence artifacts are not modified by this helper',
        'operator_next_steps': [
            'Review blockers before promoting the ISO or accepting firstboot handoff evidence.',
            'Regenerate the firstboot handoff if required artifacts are missing or stale.',
            'Keep generated manifests with release evidence so reviewers can reproduce artifact provenance by hash.',
        ],
    }


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def write_markdown(path: Path, manifest: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        '# Host VM Firstboot Handoff Manifest',
        '',
        f"- Decision: `{manifest['decision']}`",
        f"- Release gate: `{manifest['release_gate']}`",
        f"- Bundle status: `{manifest['bundle_status']}`",
        f"- Handoff decision: `{manifest['handoff_decision']}`",
        f"- Receipt decision: `{manifest['receipt_decision']}`",
        '',
        '## Blockers',
        '',
    ]
    blockers = manifest.get('blockers') or []
    lines.extend(f'- `{blocker}`' for blocker in blockers) if blockers else lines.append('- None.')
    lines.extend(['', '## Artifacts', ''])
    for artifact in manifest.get('artifacts', []):
        required = 'required' if artifact.get('required') else 'optional'
        status = 'present' if artifact.get('exists') else 'missing'
        digest = artifact.get('sha256') or 'n/a'
        lines.append(f"- `{artifact['name']}` ({required}, {status}) — `{artifact['path']}` — sha256 `{digest}`")
    lines.extend([
        '',
        '## Safety and privacy',
        '',
        f"- {manifest['safe_default']}",
        f"- {manifest['privacy_note']}",
        '',
        '## Rollback',
        '',
        f"- {manifest['rollback_note']}",
        '',
        '## Operator next steps',
        '',
    ])
    lines.extend(f'- {step}' for step in manifest.get('operator_next_steps', []))
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a privacy-safe manifest for host/VM firstboot handoff artifacts.')
    parser.add_argument('--bundle', default=str(DEFAULT_BUNDLE))
    parser.add_argument('--bundle-report', default=str(DEFAULT_BUNDLE_REPORT))
    parser.add_argument('--receipt', default=str(DEFAULT_RECEIPT))
    parser.add_argument('--receipt-markdown', default=str(DEFAULT_RECEIPT_MARKDOWN))
    parser.add_argument('--handoff-index', default=str(DEFAULT_HANDOFF_INDEX))
    parser.add_argument('--handoff-markdown', default=str(DEFAULT_HANDOFF_MARKDOWN))
    parser.add_argument('--manifest', default=str(DEFAULT_MANIFEST))
    parser.add_argument('--markdown', default=str(DEFAULT_MARKDOWN))
    parser.add_argument('--require-ready', action='store_true')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    manifest = build_manifest(args)
    write_json(Path(args.manifest), manifest)
    write_markdown(Path(args.markdown), manifest)
    print(json.dumps({'decision': manifest['decision'], 'ok': manifest['ok'], 'manifest': args.manifest}, sort_keys=True))
    return 0 if manifest['ok'] or not args.require_ready else 6


if __name__ == '__main__':
    sys.exit(main())
