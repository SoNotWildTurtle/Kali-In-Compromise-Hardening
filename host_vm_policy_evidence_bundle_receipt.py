#!/usr/bin/env python3
# MINC - Defensive host/VM policy evidence receipt gate.
# Purpose: turn existing aggregate evidence bundles into auditable handoff decisions.

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_BUNDLE = Path('/var/lib/host_vm_comm_guard/policy_evidence_bundle.json')
DEFAULT_OUTPUT = Path('/var/lib/host_vm_comm_guard/policy_evidence_bundle_receipt.json')
DEFAULT_MARKDOWN = Path('/var/log/host_vm_policy_evidence_bundle_receipt.md')


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


def load_bundle(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {'_error': 'missing_bundle'}
    except json.JSONDecodeError as exc:
        return {'_error': f'parse_error: {type(exc).__name__}: {exc}'}
    if not isinstance(data, dict):
        return {'_error': 'parse_error: expected JSON object'}
    return data


def component_statuses(bundle: Dict[str, Any]) -> List[Dict[str, str]]:
    components = bundle.get('components', [])
    if not isinstance(components, list):
        return []
    result: List[Dict[str, str]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        result.append({
            'name': str(component.get('name', 'unknown')),
            'status': str(component.get('status', 'unknown')),
            'required': str(bool(component.get('required', False))).lower(),
        })
    return result


def action_items(status: str, review_items: List[str], allow_warning_approval: bool) -> List[str]:
    if status == 'pass':
        return ['Attach this passing receipt to release, firstboot, or recovery handoff notes.']
    if status == 'warn' and allow_warning_approval:
        return ['Warnings were accepted explicitly; review warning components before promotion.']
    if status == 'warn':
        return ['Resolve or explicitly accept warning-only evidence before promotion.'] + [f'Review warning component: {item}' for item in review_items]
    if status in {'fail', 'review'}:
        return ['Do not promote until blockers are reviewed and regenerated evidence is attached.'] + [f'Review blocker component: {item}' for item in review_items]
    return ['Unknown or missing bundle status; regenerate the evidence bundle and inspect component schemas.']


def decide(bundle: Dict[str, Any], bundle_path: Path, allow_warning_approval: bool) -> Dict[str, Any]:
    error = bundle.get('_error')
    if error:
        status = 'missing' if error == 'missing_bundle' else 'invalid'
        review_items = [str(error)]
        components: List[Dict[str, str]] = []
        ok = False
    else:
        status = str(bundle.get('status', 'unknown')).lower()
        raw_items = bundle.get('review_items', [])
        review_items = [str(item) for item in raw_items if str(item)] if isinstance(raw_items, list) else []
        components = component_statuses(bundle)
        ok = status == 'pass' or (status == 'warn' and allow_warning_approval)
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'decision': 'approved' if ok else 'deferred',
        'ok': ok,
        'bundle_path': str(bundle_path),
        'bundle_sha256': sha256_file(bundle_path),
        'bundle_status': status,
        'allow_warning_approval': allow_warning_approval,
        'component_statuses': components,
        'review_items': review_items,
        'action_items': action_items(status, review_items, allow_warning_approval),
        'safe_default': 'read-only receipt gate; no live host, VM, model, dataset, approval, or restore state was changed',
        'privacy_note': 'derived from aggregate bundle metadata only; raw logs, captures, credentials, hostnames, usernames, and secrets are not embedded',
        'rollback_note': 'remove the generated receipt and revert this additive utility, test, docs, and packaging entry',
        'release_gate': 'pass' if ok else 'stop',
    }


def write_json(path: Path, receipt: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def markdown_lines(receipt: Dict[str, Any]) -> List[str]:
    lines = [
        '# Host VM Policy Evidence Bundle Receipt',
        '',
        f"- Decision: `{receipt.get('decision')}`",
        f"- Release gate: `{receipt.get('release_gate')}`",
        f"- Bundle status: `{receipt.get('bundle_status')}`",
        f"- Bundle SHA-256: `{receipt.get('bundle_sha256')}`",
        '',
        '## Component statuses',
        '',
        '| Component | Status | Required |',
        '| --- | --- | --- |',
    ]
    for component in receipt.get('component_statuses', []):
        if isinstance(component, dict):
            lines.append(f"| `{component.get('name')}` | `{component.get('status')}` | `{component.get('required')}` |")
    if not receipt.get('component_statuses'):
        lines.append('| `_bundle_` | `missing_or_invalid` | `true` |')
    lines.extend(['', '## Action items', ''])
    for item in receipt.get('action_items', []):
        lines.append(f'- {item}')
    lines.extend(['', '## Safety and privacy', '', f"- {receipt.get('safe_default')}", f"- {receipt.get('privacy_note')}", '', '## Rollback', '', f"- {receipt.get('rollback_note')}"])
    return lines


def write_markdown(path: Path, receipt: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(markdown_lines(receipt)) + '\n', encoding='utf-8')


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a read-only go/no-go receipt from a host/VM policy evidence bundle.')
    parser.add_argument('--bundle', default=str(DEFAULT_BUNDLE))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--markdown', default=str(DEFAULT_MARKDOWN))
    parser.add_argument('--allow-warning-approval', action='store_true')
    parser.add_argument('--require-ready', action='store_true')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    bundle_path = Path(args.bundle)
    receipt = decide(load_bundle(bundle_path), bundle_path, args.allow_warning_approval)
    write_json(Path(args.output), receipt)
    write_markdown(Path(args.markdown), receipt)
    print(json.dumps({'decision': receipt['decision'], 'ok': receipt['ok'], 'output': args.output}, sort_keys=True))
    return 0 if receipt['ok'] or not args.require_ready else 5


if __name__ == '__main__':
    sys.exit(main())
