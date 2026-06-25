#!/usr/bin/env python3
# MINC - Defensive host/VM policy attestation verifier.
# Purpose: compare local posture snapshots against a known-good baseline without changing live policy by default.

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_CURRENT = Path('/var/lib/host_vm_comm_guard/policy_attestation.json')
DEFAULT_BASELINE = Path('/var/lib/host_vm_comm_guard/policy_attestation.baseline.json')
DEFAULT_OUTPUT = Path('/var/lib/host_vm_comm_guard/policy_verify.json')
DEFAULT_REPORT = Path('/var/log/host_vm_policy_verify.report')

Decision = Tuple[str, str, str]

CRITICAL_GUARD_PATHS = {
    '/etc/host_vm_comm_guard.conf',
    '/etc/nftables.d/host_vm_comm_guard.nft',
}
CRITICAL_UNITS = {
    'host_vm_comm_guard.service',
    'host_vm_policy_attest.timer',
    'nn_ids_model_audit.timer',
    'nn_ids_audit_gate.timer',
    'nn_ids_restore.timer',
}


def load_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise SystemExit(f'missing required JSON file: {path}') from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f'could not parse JSON file {path}: {exc}') from exc
    if not isinstance(data, dict):
        raise SystemExit(f'expected JSON object in {path}')
    return data


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def guard_files_by_path(snapshot: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    files: Dict[str, Dict[str, Any]] = {}
    for item in snapshot.get('guard_files', []):
        if isinstance(item, dict) and 'path' in item:
            files[str(item['path'])] = item
    return files


def compare_guard_files(base: Dict[str, Any], current: Dict[str, Any]) -> List[Decision]:
    decisions: List[Decision] = []
    base_files = guard_files_by_path(base)
    current_files = guard_files_by_path(current)
    for path in sorted(set(base_files) | set(current_files)):
        b = base_files.get(path, {})
        c = current_files.get(path, {})
        critical = path in CRITICAL_GUARD_PATHS
        severity = 'critical' if critical else 'warning'
        if b.get('exists') != c.get('exists'):
            decisions.append((severity, f'guard file existence drift: {path}', f"baseline={b.get('exists')} current={c.get('exists')}"))
            continue
        if b.get('sha256') != c.get('sha256'):
            decisions.append((severity, f'guard file hash drift: {path}', f"baseline={b.get('sha256')} current={c.get('sha256')}"))
        if b.get('mode') != c.get('mode'):
            decisions.append(('warning', f'guard file mode drift: {path}', f"baseline={b.get('mode')} current={c.get('mode')}"))
    return decisions


def compare_nftables(base: Dict[str, Any], current: Dict[str, Any]) -> List[Decision]:
    decisions: List[Decision] = []
    b = base.get('nftables', {}) if isinstance(base.get('nftables'), dict) else {}
    c = current.get('nftables', {}) if isinstance(current.get('nftables'), dict) else {}
    for field in ('table_present', 'contains_guard_prefixes'):
        if b.get(field) != c.get(field):
            decisions.append(('critical', f'nftables guard drift: {field}', f"baseline={b.get(field)} current={c.get(field)}"))
    if b.get('stdout_sha256') and c.get('stdout_sha256') and b.get('stdout_sha256') != c.get('stdout_sha256'):
        decisions.append(('warning', 'nftables ruleset digest changed', f"baseline={b.get('stdout_sha256')} current={c.get('stdout_sha256')}"))
    return decisions


def compare_systemd(base: Dict[str, Any], current: Dict[str, Any]) -> List[Decision]:
    decisions: List[Decision] = []
    b_units = base.get('systemd', {}) if isinstance(base.get('systemd'), dict) else {}
    c_units = current.get('systemd', {}) if isinstance(current.get('systemd'), dict) else {}
    for unit in sorted(set(b_units) | set(c_units) | CRITICAL_UNITS):
        b = b_units.get(unit, {}) if isinstance(b_units.get(unit), dict) else {}
        c = c_units.get(unit, {}) if isinstance(c_units.get(unit), dict) else {}
        severity = 'critical' if unit in CRITICAL_UNITS else 'warning'
        for field in ('active', 'enabled'):
            if b.get(field) != c.get(field):
                decisions.append((severity, f'systemd {field} drift: {unit}', f"baseline={b.get(field)} current={c.get(field)}"))
    return decisions


def compare_ids(base: Dict[str, Any], current: Dict[str, Any]) -> List[Decision]:
    decisions: List[Decision] = []
    b_gate = base.get('ids_audit_gate', {}) if isinstance(base.get('ids_audit_gate'), dict) else {}
    c_gate = current.get('ids_audit_gate', {}) if isinstance(current.get('ids_audit_gate'), dict) else {}
    if b_gate.get('decision') != c_gate.get('decision'):
        severity = 'critical' if c_gate.get('decision') in {'restore', 'retrain'} else 'warning'
        decisions.append((severity, 'NN IDS audit gate decision drift', f"baseline={b_gate.get('decision')} current={c_gate.get('decision')}"))
    b_audit = base.get('ids_model_audit', {}) if isinstance(base.get('ids_model_audit'), dict) else {}
    c_audit = current.get('ids_model_audit', {}) if isinstance(current.get('ids_model_audit'), dict) else {}
    for field in ('balanced_accuracy', 'macro_f1', 'robustness_index', 'drift_detected'):
        if b_audit.get(field) != c_audit.get(field):
            decisions.append(('warning', f'NN IDS model audit drift: {field}', f"baseline={b_audit.get(field)} current={c_audit.get(field)}"))
    return decisions


def compare_snapshots(baseline: Dict[str, Any], current: Dict[str, Any]) -> List[Decision]:
    findings: List[Decision] = []
    findings.extend(compare_guard_files(baseline, current))
    findings.extend(compare_nftables(baseline, current))
    findings.extend(compare_systemd(baseline, current))
    findings.extend(compare_ids(baseline, current))
    return findings


def summarize_decision(findings: Iterable[Decision], strict: bool = False) -> str:
    severities = [severity for severity, _, _ in findings]
    if 'critical' in severities:
        return 'restore_review'
    if 'warning' in severities:
        return 'restore_review' if strict else 'watch'
    return 'accept'


def write_report(result: Dict[str, Any], report_path: Path) -> None:
    ensure_parent(report_path)
    lines = [
        f"created_utc={result['created_utc']}",
        f"decision={result['decision']}",
        f"critical_findings={result['critical_findings']}",
        f"warning_findings={result['warning_findings']}",
        f"baseline={result['baseline']}",
        f"current={result['current']}",
    ]
    for finding in result.get('findings', [])[:20]:
        lines.append(f"finding={finding['severity']}|{finding['title']}|{finding['detail']}")
    report_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(report_path, 0o640)
    except OSError:
        pass


def init_baseline(current: Path, baseline: Path, force: bool = False) -> Dict[str, Any]:
    if baseline.exists() and not force:
        return {
            'decision': 'baseline_exists',
            'baseline': str(baseline),
            'current': str(current),
            'message': 'baseline already exists; use --force-baseline to replace it intentionally',
        }
    if not current.exists():
        raise SystemExit(f'cannot initialize baseline because current snapshot is missing: {current}')
    ensure_parent(baseline)
    shutil.copy2(current, baseline)
    try:
        os.chmod(baseline, 0o640)
    except OSError:
        pass
    return {
        'decision': 'baseline_initialized',
        'baseline': str(baseline),
        'current': str(current),
        'message': 'known-good baseline initialized from current local attestation snapshot',
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Verify host/VM policy attestation against a known-good baseline.')
    parser.add_argument('--current', default=str(DEFAULT_CURRENT), help='current attestation snapshot JSON')
    parser.add_argument('--baseline', default=str(DEFAULT_BASELINE), help='known-good attestation baseline JSON')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT), help='verification result JSON path')
    parser.add_argument('--report', default=str(DEFAULT_REPORT), help='compact verification report path')
    parser.add_argument('--init-baseline', action='store_true', help='initialize baseline from current snapshot if absent')
    parser.add_argument('--force-baseline', action='store_true', help='replace baseline when used with --init-baseline')
    parser.add_argument('--strict', action='store_true', help='treat warnings as restore-review decisions')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    current_path = Path(args.current)
    baseline_path = Path(args.baseline)
    output_path = Path(args.output)
    report_path = Path(args.report)

    if args.init_baseline:
        result = init_baseline(current_path, baseline_path, force=args.force_baseline)
        result['created_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        result['critical_findings'] = 0
        result['warning_findings'] = 0
        result['findings'] = []
        ensure_parent(output_path)
        output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        write_report(result, report_path)
        print(json.dumps(result, sort_keys=True))
        return 0

    baseline = load_json(baseline_path)
    current = load_json(current_path)
    findings = compare_snapshots(baseline, current)
    critical = sum(1 for severity, _, _ in findings if severity == 'critical')
    warning = sum(1 for severity, _, _ in findings if severity == 'warning')
    result = {
        'schema_version': 1,
        'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'purpose': 'rollback-safe verification of host/VM communication policy and NN IDS posture attestation',
        'baseline': str(baseline_path),
        'current': str(current_path),
        'decision': summarize_decision(findings, strict=args.strict),
        'critical_findings': critical,
        'warning_findings': warning,
        'findings': [
            {'severity': severity, 'title': title, 'detail': detail}
            for severity, title, detail in findings
        ],
        'safe_default': 'review-only; no firewall, systemd, model, or host state was changed',
    }
    ensure_parent(output_path)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        os.chmod(output_path, 0o640)
    except OSError:
        pass
    write_report(result, report_path)
    print(json.dumps({'decision': result['decision'], 'critical': critical, 'warning': warning, 'output': str(output_path)}, sort_keys=True))
    return 0 if result['decision'] in {'accept', 'watch'} else 1


if __name__ == '__main__':
    sys.exit(main())
