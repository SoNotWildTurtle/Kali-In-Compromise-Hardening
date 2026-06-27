#!/usr/bin/env python3
# MINC - Defensive host/VM firstboot handoff evidence gate.
# Purpose: compose privacy-safe policy bundle and receipt artifacts for review.

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import host_vm_policy_evidence_bundle as evidence_bundle
import host_vm_policy_evidence_bundle_receipt as evidence_receipt

DEFAULT_BUNDLE = Path('/var/lib/host_vm_comm_guard/policy_evidence_bundle.json')
DEFAULT_BUNDLE_REPORT = Path('/var/log/host_vm_policy_evidence_bundle.report')
DEFAULT_RECEIPT = Path('/var/lib/host_vm_comm_guard/policy_evidence_bundle_receipt.json')
DEFAULT_RECEIPT_MARKDOWN = Path('/var/log/host_vm_policy_evidence_bundle_receipt.md')
DEFAULT_INDEX = Path('/var/log/host_vm_policy_firstboot_handoff.json')
DEFAULT_MARKDOWN = Path('/var/log/host_vm_policy_firstboot_handoff.md')


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


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def write_markdown(path: Path, index: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        '# Host VM Firstboot Policy Handoff',
        '',
        f"- Decision: `{index['decision']}`",
        f"- Release gate: `{index['release_gate']}`",
        f"- Bundle status: `{index['bundle_status']}`",
        f"- Receipt: `{index['receipt_path']}`",
        f"- Bundle: `{index['bundle_path']}`",
        '',
        '## Review items',
        '',
    ]
    review_items = index.get('review_items') or []
    if review_items:
        lines.extend(f'- `{item}`' for item in review_items)
    else:
        lines.append('- None reported by aggregate evidence.')
    lines.extend([
        '',
        '## Safety and privacy',
        '',
        f"- {index['safe_default']}",
        f"- {index['privacy_note']}",
        '',
        '## Rollback',
        '',
        f"- {index['rollback_note']}",
    ])
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def build_index(bundle_path: Path, receipt_path: Path, receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'component': 'host_vm_policy_firstboot_handoff',
        'decision': receipt.get('decision', 'deferred'),
        'ok': bool(receipt.get('ok', False)),
        'release_gate': receipt.get('release_gate', 'stop'),
        'bundle_status': receipt.get('bundle_status', 'unknown'),
        'bundle_path': str(bundle_path),
        'bundle_sha256': sha256_file(bundle_path),
        'receipt_path': str(receipt_path),
        'receipt_sha256': sha256_file(receipt_path),
        'review_items': receipt.get('review_items', []),
        'action_items': receipt.get('action_items', []),
        'safe_default': 'read-only firstboot handoff; no host, VM, firewall, service, model, dataset, approval, or restore state was changed',
        'privacy_note': 'derived from aggregate evidence and receipt metadata only; raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, and datasets are not embedded',
        'rollback_note': 'delete generated firstboot handoff, receipt, and bundle artifacts or revert this additive helper and its packaging/docs/tests',
    }


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a privacy-safe firstboot handoff from host/VM policy evidence.')
    parser.add_argument('--attestation', default=str(evidence_bundle.COMPONENTS['policy_attestation'][0]))
    parser.add_argument('--verify', default=str(evidence_bundle.COMPONENTS['policy_verify'][0]))
    parser.add_argument('--restore-plan', default=str(evidence_bundle.COMPONENTS['policy_restore_plan'][0]))
    parser.add_argument('--approval-check', default=str(evidence_bundle.COMPONENTS['policy_approval_check'][0]))
    parser.add_argument('--ids-model-audit', default=str(evidence_bundle.COMPONENTS['nn_ids_model_audit'][0]))
    parser.add_argument('--ids-audit-gate', default=str(evidence_bundle.COMPONENTS['nn_ids_audit_gate'][0]))
    parser.add_argument('--ids-health-evidence', default=str(evidence_bundle.COMPONENTS['nn_ids_health_evidence'][0]))
    parser.add_argument('--bundle', default=str(DEFAULT_BUNDLE))
    parser.add_argument('--bundle-report', default=str(DEFAULT_BUNDLE_REPORT))
    parser.add_argument('--receipt', default=str(DEFAULT_RECEIPT))
    parser.add_argument('--receipt-markdown', default=str(DEFAULT_RECEIPT_MARKDOWN))
    parser.add_argument('--index', default=str(DEFAULT_INDEX))
    parser.add_argument('--markdown', default=str(DEFAULT_MARKDOWN))
    parser.add_argument('--allow-warning-approval', action='store_true')
    parser.add_argument('--require-ready', action='store_true')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    bundle_path = Path(args.bundle)
    bundle = evidence_bundle.build_bundle(args)
    evidence_bundle.write_json(bundle_path, bundle)
    evidence_bundle.write_report(Path(args.bundle_report), bundle)

    receipt = evidence_receipt.decide(bundle, bundle_path, args.allow_warning_approval)
    receipt_path = Path(args.receipt)
    evidence_receipt.write_json(receipt_path, receipt)
    evidence_receipt.write_markdown(Path(args.receipt_markdown), receipt)

    index = build_index(bundle_path, receipt_path, receipt)
    write_json(Path(args.index), index)
    write_markdown(Path(args.markdown), index)
    print(json.dumps({'decision': index['decision'], 'ok': index['ok'], 'index': args.index}, sort_keys=True))
    return 0 if index['ok'] or not args.require_ready else 6


if __name__ == '__main__':
    sys.exit(main())
