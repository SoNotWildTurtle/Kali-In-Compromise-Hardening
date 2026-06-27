#!/usr/bin/env python3
# MINC - Defensive host/VM policy evidence bundle generator.
# Purpose: collect privacy-safe posture summaries for local review without changing live state.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

STATE_DIR = Path('/var/lib/host_vm_comm_guard')
NN_IDS_DIR = Path('/var/lib/nn_ids')
DEFAULT_OUTPUT = STATE_DIR / 'policy_evidence_bundle.json'
DEFAULT_REPORT = Path('/var/log/host_vm_policy_evidence_bundle.report')
SENSITIVE_HINTS = ('secret', 'token', 'credential', 'password', 'private_key', 'signature')
REVIEW_DECISIONS = {'restore_review', 'manual_restore_review_required', 'restore_blocked_missing_known_good', 'approval_rejected', 'restore', 'retrain'}
PASS_DECISIONS = {'accept', 'no_restore_needed', 'already_restored', 'approval_valid', 'pass', 'ok'}

COMPONENTS = {
    'policy_attestation': (STATE_DIR / 'policy_attestation.json', True, ('schema_version', 'created_utc', 'snapshot_sha256')),
    'policy_verify': (STATE_DIR / 'policy_verify.json', True, ('schema_version', 'created_utc', 'decision', 'critical_findings', 'warning_findings')),
    'policy_restore_plan': (STATE_DIR / 'policy_restore_plan.json', False, ('schema_version', 'created_utc', 'decision', 'verify_decision', 'changes_live_state')),
    'policy_approval_check': (STATE_DIR / 'policy_restore_approval_check.json', False, ('schema_version', 'created_utc', 'decision', 'plan_decision', 'changes_live_state')),
    'nn_ids_model_audit': (NN_IDS_DIR / 'model_audit.json', False, ('schema_version', 'created_utc', 'decision', 'balanced_accuracy', 'macro_f1', 'robustness_index', 'drift_detected')),
    'nn_ids_audit_gate': (NN_IDS_DIR / 'audit_gate.json', False, ('schema_version', 'created_utc', 'decision', 'reason')),
    'nn_ids_health_evidence': (NN_IDS_DIR / 'health_evidence.json', False, ('component', 'generated_at', 'status', 'ok', 'failing_controls', 'warning_controls')),
}


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in SENSITIVE_HINTS)


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {'_missing': True}
    except json.JSONDecodeError as exc:
        return {'_parse_error': f'{type(exc).__name__}: {exc}'}
    if not isinstance(data, dict):
        return {'_parse_error': 'expected JSON object'}
    return data


def safe_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [item if isinstance(item, (str, int, float, bool)) or item is None else type(item).__name__ for item in value[:20]]
    if isinstance(value, dict):
        return {str(k): safe_value(v) for k, v in list(value.items())[:20] if not sensitive_key(str(k))}
    return type(value).__name__


def classify(data: Dict[str, Any]) -> str:
    decision = str(data.get('decision', data.get('status', 'present'))).lower()
    if decision in REVIEW_DECISIONS or data.get('ok') is False or data.get('critical_findings', 0) or data.get('failing_controls'):
        return 'review'
    if data.get('warning_findings', 0) or data.get('warning_controls') or decision in {'warn', 'warning', 'degraded'}:
        return 'warn'
    if decision in PASS_DECISIONS:
        return 'pass'
    return 'present'


def summarize(name: str, path: Path, required: bool, keys: Iterable[str]) -> Dict[str, Any]:
    data = load_json(path)
    item: Dict[str, Any] = {'name': name, 'path': str(path), 'required': required, 'exists': path.exists(), 'sha256': sha256_file(path)}
    if data.get('_missing'):
        item['status'] = 'missing_required' if required else 'missing_optional'
        return item
    if data.get('_parse_error'):
        item['status'] = 'parse_error'
        item['parse_error'] = data['_parse_error']
        return item
    item['summary'] = {key: safe_value(data[key]) for key in keys if key in data and not sensitive_key(key)}
    item['status'] = classify(data)
    return item


def overall_status(components: Iterable[Dict[str, Any]]) -> str:
    components = list(components)
    if any(c.get('required') and c.get('status') in {'missing_required', 'parse_error'} for c in components):
        return 'fail'
    statuses = {str(c.get('status')) for c in components}
    if 'review' in statuses:
        return 'review'
    if 'warn' in statuses:
        return 'warn'
    return 'pass'


def build_bundle(args: argparse.Namespace) -> Dict[str, Any]:
    paths = {
        'policy_attestation': Path(args.attestation),
        'policy_verify': Path(args.verify),
        'policy_restore_plan': Path(args.restore_plan),
        'policy_approval_check': Path(args.approval_check),
        'nn_ids_model_audit': Path(args.ids_model_audit),
        'nn_ids_audit_gate': Path(args.ids_audit_gate),
        'nn_ids_health_evidence': Path(args.ids_health_evidence),
    }
    components = [summarize(name, paths.get(name, spec[0]), spec[1], spec[2]) for name, spec in sorted(COMPONENTS.items())]
    status = overall_status(components)
    review_items = [c['name'] for c in components if c.get('status') in {'review', 'warn', 'missing_required', 'parse_error'}]
    return {
        'schema_version': 1,
        'created_utc': utc_now(),
        'purpose': 'privacy-safe local evidence bundle for host/VM policy, rollback, approval, and NN IDS posture review',
        'status': status,
        'ok': status == 'pass',
        'component_count': len(components),
        'review_items': review_items,
        'components': components,
        'safe_default': 'read-only; no firewall, systemd, model, host, VM, or approval state was changed',
        'privacy_note': 'full JSON inputs are not embedded; only digests and non-sensitive summary fields are recorded',
    }


def write_json(path: Path, data: Dict[str, Any]) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def write_report(path: Path, bundle: Dict[str, Any]) -> None:
    ensure_parent(path)
    lines = [
        f"created_utc={bundle.get('created_utc')}",
        f"status={bundle.get('status')}",
        f"ok={bundle.get('ok')}",
        f"review_items={','.join(str(item) for item in bundle.get('review_items', []))}",
        f"safe_default={bundle.get('safe_default')}",
    ]
    for component in bundle.get('components', []):
        if isinstance(component, dict):
            lines.append(f"component={component.get('name')}|{component.get('status')}|{component.get('sha256')}")
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a read-only host/VM policy and NN IDS evidence bundle.')
    parser.add_argument('--attestation', default=str(COMPONENTS['policy_attestation'][0]))
    parser.add_argument('--verify', default=str(COMPONENTS['policy_verify'][0]))
    parser.add_argument('--restore-plan', default=str(COMPONENTS['policy_restore_plan'][0]))
    parser.add_argument('--approval-check', default=str(COMPONENTS['policy_approval_check'][0]))
    parser.add_argument('--ids-model-audit', default=str(COMPONENTS['nn_ids_model_audit'][0]))
    parser.add_argument('--ids-audit-gate', default=str(COMPONENTS['nn_ids_audit_gate'][0]))
    parser.add_argument('--ids-health-evidence', default=str(COMPONENTS['nn_ids_health_evidence'][0]))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--report', default=str(DEFAULT_REPORT))
    parser.add_argument('--require-pass', action='store_true', help='exit non-zero unless every required signal is healthy')
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    bundle = build_bundle(args)
    write_json(Path(args.output), bundle)
    write_report(Path(args.report), bundle)
    print(json.dumps({'status': bundle['status'], 'ok': bundle['ok'], 'output': args.output}, sort_keys=True))
    return 0 if not args.require_pass or bundle['ok'] else 4


if __name__ == '__main__':
    sys.exit(main())
