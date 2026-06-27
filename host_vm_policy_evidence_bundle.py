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
from typing import Any, Dict, Iterable, List, Optional

STATE_DIR = Path('/var/lib/host_vm_comm_guard')
NN_IDS_DIR = Path('/var/lib/nn_ids')
DEFAULT_OUTPUT = STATE_DIR / 'policy_evidence_bundle.json'
DEFAULT_REPORT = Path('/var/log/host_vm_policy_evidence_bundle.report')

DEFAULT_COMPONENTS = {
    'policy_attestation': {
        'path': STATE_DIR / 'policy_attestation.json',
        'required': True,
        'summary_keys': ('schema_version', 'created_utc', 'snapshot_sha256'),
    },
    'policy_verify': {
        'path': STATE_DIR / 'policy_verify.json',
        'required': True,
        'summary_keys': ('schema_version', 'created_utc', 'decision', 'critical_findings', 'warning_findings'),
    },
    'policy_restore_plan': {
        'path': STATE_DIR / 'policy_restore_plan.json',
        'required': False,
        'summary_keys': ('schema_version', 'created_utc', 'decision', 'verify_decision', 'changes_live_state'),
    },
    'policy_approval_check': {
        'path': STATE_DIR / 'policy_restore_approval_check.json',
        'required': False,
        'summary_keys': ('schema_version', 'created_utc', 'decision', 'plan_decision', 'changes_live_state'),
    },
    'nn_ids_model_audit': {
        'path': NN_IDS_DIR / 'model_audit.json',
        'required': False,
        'summary_keys': ('schema_version', 'created_utc', 'decision', 'balanced_accuracy', 'macro_f1', 'robustness_index', 'drift_detected'),
    },
    'nn_ids_audit_gate': {
        'path': NN_IDS_DIR / 'audit_gate.json',
        'required': False,
        'summary_keys': ('schema_version', 'created_utc', 'decision', 'reason'),
    },
    'nn_ids_health_evidence': {
        'path': NN_IDS_DIR / 'health_evidence.json',
        'required': False,
        'summary_keys': ('component', 'generated_at', 'status', 'ok', 'failing_controls', 'warning_controls'),
    },
}

REVIEW_DECISIONS = {
    'restore_review',
    'manual_restore_review_required',
    'restore_blocked_missing_known_good',
    'approval_rejected',
    'restore_required',
    'retrain',
    'restore',
}
PASS_DECISIONS = {
    'accept',
    'no_restore_needed',
    'already_restored',
    'approval_valid',
    'pass',
    'ok',
}
SENSITIVE_KEY_HINTS = ('secret', 'token', 'credential', 'password', 'private_key', 'signature')


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


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
        return {'exists': False, 'missing': True}
    except json.JSONDecodeError as exc:
        return {'exists': True, 'parse_error': f'{type(exc).__name__}: {exc}'}
    if not isinstance(data, dict):
        return {'exists': True, 'parse_error': 'expected JSON object'}
    return data


def safe_scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        clean: List[Any] = []
        for item in value[:20]:
            if isinstance(item, (str, int, float, bool)) or item is None:
                clean.append(item)
            else:
                clean.append(type(item).__name__)
        return clean
    if isinstance(value, dict):
        return {str(k): safe_scalar(v) for k, v in list(value.items())[:20] if not sensitive_key(str(k))}
    return type(value).__name__


def sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in SENSITIVE_KEY_HINTS)


def summarize_component(name: str, path: Path, required: bool, summary_keys: Iterable[str]) -> Dict[str, Any]:
    data = load_json(path)
    exists = path.exists()
    summary: Dict[str, Any] = {
        'name': name,
        'path': str(path),
        'required': required,
        'exists': exists,
        'sha256': sha256_file(path),
    }
    if data.get('missing'):
        summary['status'] = 'missing_required' if required else 'missing_optional'
        return summary
    if 'parse_error' in data:
        summary['status'] = 'parse_error'
        summary['parse_error'] = data['parse_error']
        return summary

    extracted: Dict[str, Any] = {}
    for key in summary_keys:
        if key in data and not sensitive_key(key):
            extracted[key] = safe_scalar(data[key])
    summary['summary'] = extracted
    summary['status'] = classify_component(data)
    return summary


def classify_component(data: Dict[str, Any]) -> str:
    decision = str(data.get('decision', data.get('status', 'present'))).lower()
    if decision in REVIEW_DECISIONS:
        return 'review'
    if decision in PASS_DECISIONS:
        return 'pass'
    if data.get('ok') is False:
        return 'review'
    if data.get('critical_findings', 0):
        return 'review'
    if data.get('failing_controls'):
        return 'review'
    if data.get('warning_findings', 0) or data.get('warning_controls'):
        return 'warn'
    if decision in {'warn', 'warning', 'degraded'}:
        return 'warn'
    return 'present'


def bundle_status(components: Iterable[Dict[str, Any]]) -> str:
    statuses = [str(component.get('status')) for component in components]
    required_missing_or_bad = any(
        component.get('required') and component.get('status') in {'missing_required', 'parse_error'}
        for component in components
    )
    if required_missing_or_bad:
        return 'fail'
    if 'review' in statuses:
        return 'review'
    if 'warn' in statuses:
        return 'warn'
    return 'pass'


def build_bundle(args: argparse.Namespace) -> Dict[str, Any]:
    component_specs = dict(DEFAULT_COMPONENTS)
    component_specs['policy_attestation'] = {**component_specs['policy_attestation'], 'path': Path(args.attestation)}
    component_specs['policy_verify'] = {**component_specs['policy_verify'], 'path': Path(args.verify)}
    component_specs['policy_restore_plan'] = {**component_specs['policy_restore_plan'], 'path': Path(args.restore_plan)}
    component_specs['policy_approval_check'] = {**component_specs['policy_approval_check'], 'path': Path(args.approval_check)}
    component_specs['nn_ids_model_audit'] = {**component_specs['nn_ids_model_audit'], 'path': Path(args.ids_model_audit)}
    component_specs['nn_ids_audit_gate'] = {**component_specs['nn_ids_audit_gate'], 'path': Path(args.ids_audit_gate)}
    component_specs['nn_ids_health_evidence'] = {**component_specs['nn_ids_health_evidence'], 'path': Path(args.ids_health_evidence)}

    components = [
        summarize_component(
            name,
            Path(spec['path']),
            bool(spec['required']),
            spec['summary_keys'],
        )
        for name, spec in sorted(component_specs.items())
    ]
    status = bundle_status(components)
    review_items = [component['name'] for component in components if component.get('status') in {'review', 'warn', 'missing_required', 'parse_error'}]
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


def write_report(path: Path, bundle: Dict[str, Any]) -> None:
    ensure_parent(path)
    lines = [
        f"created_utc={bundle.get('created_utc')}",
        f"status={bundle.get('status')}",
        f"ok={bundle.get('ok')}",
        f"component_count={bundle.get('component_count')}",
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


def write_json(path: Path, data: Dict[str, Any]) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a read-only host/VM policy and NN IDS evidence bundle.')
    parser.add_argument('--attestation', default=str(DEFAULT_COMPONENTS['policy_attestation']['path']), help='policy attestation JSON path')
    parser.add_argument('--verify', default=str(DEFAULT_COMPONENTS['policy_verify']['path']), help='policy verification JSON path')
    parser.add_argument('--restore-plan', default=str(DEFAULT_COMPONENTS['policy_restore_plan']['path']), help='restore plan JSON path')
    parser.add_argument('--approval-check', default=str(DEFAULT_COMPONENTS['policy_approval_check']['path']), help='approval check JSON path')
    parser.add_argument('--ids-model-audit', default=str(DEFAULT_COMPONENTS['nn_ids_model_audit']['path']), help='NN IDS model audit JSON path')
    parser.add_argument('--ids-audit-gate', default=str(DEFAULT_COMPONENTS['nn_ids_audit_gate']['path']), help='NN IDS audit gate JSON path')
    parser.add_argument('--ids-health-evidence', default=str(DEFAULT_COMPONENTS['nn_ids_health_evidence']['path']), help='NN IDS health evidence JSON path')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT), help='bundle JSON output path')
    parser.add_argument('--report', default=str(DEFAULT_REPORT), help='compact line-oriented report path')
    parser.add_argument('--require-pass', action='store_true', help='exit non-zero unless every required signal is healthy')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    bundle = build_bundle(args)
    write_json(Path(args.output), bundle)
    write_report(Path(args.report), bundle)
    print(json.dumps({'status': bundle['status'], 'ok': bundle['ok'], 'output': args.output}, sort_keys=True))
    return 0 if not args.require_pass or bundle['ok'] else 4


if __name__ == '__main__':
    sys.exit(main())
