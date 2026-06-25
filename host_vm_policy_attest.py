#!/usr/bin/env python3
# MINC - Defensive host/VM policy attestation snapshotter.
# Purpose: create local, reviewable posture snapshots for Kali guest hardening.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_OUTPUT = Path('/var/lib/host_vm_comm_guard/policy_attestation.json')
DEFAULT_SIGNATURE = Path('/var/lib/host_vm_comm_guard/policy_attestation.sig')
DEFAULT_PUBLIC_REPORT = Path('/var/log/host_vm_policy_attest.report')
DEFAULT_KEY = Path('/etc/host_vm_comm_guard/attestation_ed25519.key')
DEFAULT_NFT_POLICY = Path('/etc/nftables.d/host_vm_comm_guard.nft')
DEFAULT_GUARD_CONF = Path('/etc/host_vm_comm_guard.conf')
DEFAULT_IDS_AUDIT = Path('/var/lib/nn_ids/model_audit.json')
DEFAULT_IDS_GATE = Path('/var/lib/nn_ids/audit_gate.json')

SENSITIVE_PATH_HINTS = ('shadow', 'passwd', 'key', 'secret', 'token', 'credential')


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        'path': str(path),
        'exists': path.exists(),
    }
    if not path.exists():
        return info
    try:
        stat = path.stat()
        info.update({
            'mode': oct(stat.st_mode & 0o777),
            'size': stat.st_size,
            'mtime': int(stat.st_mtime),
            'sha256': sha256_bytes(path.read_bytes()),
        })
    except OSError as exc:
        info['error'] = f'{type(exc).__name__}: {exc}'
    return info


def safe_read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {'path': str(path), 'exists': False}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:  # noqa: BLE001 - report malformed local evidence without crashing.
        return {'path': str(path), 'exists': True, 'parse_error': f'{type(exc).__name__}: {exc}'}
    summary: Dict[str, Any] = {'path': str(path), 'exists': True, 'sha256': file_digest(path).get('sha256')}
    if isinstance(data, dict):
        for key in ('decision', 'status', 'accuracy', 'balanced_accuracy', 'macro_f1', 'robustness_index', 'drift_detected'):
            if key in data:
                summary[key] = data[key]
        if 'metrics' in data and isinstance(data['metrics'], dict):
            summary['metrics_keys'] = sorted(str(k) for k in data['metrics'].keys())
        if 'warnings' in data and isinstance(data['warnings'], list):
            summary['warning_count'] = len(data['warnings'])
    return summary


def run_command(cmd: List[str], timeout: int = 10) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {'cmd': cmd, 'available': False}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'available': True, 'timeout': timeout}
    return {
        'cmd': cmd,
        'available': True,
        'returncode': proc.returncode,
        'stdout_sha256': sha256_bytes(proc.stdout.encode()),
        'stderr_sha256': sha256_bytes(proc.stderr.encode()),
        'stdout_preview': proc.stdout.strip().splitlines()[:12],
        'stderr_preview': proc.stderr.strip().splitlines()[:8],
    }


def systemd_unit_state(units: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    states: Dict[str, Dict[str, Any]] = {}
    for unit in units:
        active = run_command(['systemctl', 'is-active', unit], timeout=5)
        enabled = run_command(['systemctl', 'is-enabled', unit], timeout=5)
        states[unit] = {
            'active_rc': active.get('returncode'),
            'active': (active.get('stdout_preview') or ['unknown'])[0],
            'enabled_rc': enabled.get('returncode'),
            'enabled': (enabled.get('stdout_preview') or ['unknown'])[0],
        }
    return states


def nft_summary() -> Dict[str, Any]:
    nft = run_command(['nft', 'list', 'table', 'inet', 'host_vm_comm_guard'], timeout=10)
    summary: Dict[str, Any] = {
        'available': nft.get('available', False),
        'returncode': nft.get('returncode'),
        'table_present': nft.get('returncode') == 0,
        'stdout_sha256': nft.get('stdout_sha256'),
    }
    preview = '\n'.join(nft.get('stdout_preview', []))
    summary['contains_guard_prefixes'] = 'host-vm-deny' in preview or 'host_vm_comm_guard' in preview
    return summary


def host_identity() -> Dict[str, Any]:
    return {
        'hostname': socket.gethostname(),
        'fqdn': socket.getfqdn(),
        'kernel': platform.release(),
        'platform': platform.platform(),
        'machine': platform.machine(),
        'python': platform.python_version(),
    }


def build_snapshot(args: argparse.Namespace) -> Dict[str, Any]:
    guard_files = [DEFAULT_GUARD_CONF, DEFAULT_NFT_POLICY]
    extra_files = [Path(p) for p in args.extra_file]
    paths = guard_files + extra_files
    snapshot = {
        'schema_version': 1,
        'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'purpose': 'local defensive attestation for Kali host/VM communication policy and NN IDS posture',
        'host': host_identity(),
        'guard_files': [file_digest(path) for path in paths],
        'nftables': nft_summary(),
        'systemd': systemd_unit_state([
            'host_vm_comm_guard.service',
            'nn_ids_model_audit.timer',
            'nn_ids_audit_gate.timer',
            'nn_ids_restore.timer',
            'host_vm_policy_attest.timer',
            'host_vm_policy_verify.timer',
        ]),
        'ids_model_audit': safe_read_json(Path(args.ids_audit)),
        'ids_audit_gate': safe_read_json(Path(args.ids_gate)),
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(',', ':')).encode('utf-8')
    snapshot['snapshot_sha256'] = sha256_bytes(canonical)
    return snapshot


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def maybe_sign(snapshot_path: Path, signature_path: Path, key_path: Path) -> Dict[str, Any]:
    if not key_path.exists():
        return {
            'signed': False,
            'reason': f'private key not present at {key_path}; snapshot remains hash-attested only',
        }
    for hint in SENSITIVE_PATH_HINTS:
        if hint in str(key_path).lower() and key_path.stat().st_mode & 0o077:
            return {
                'signed': False,
                'reason': f'private key permissions too broad for {key_path}; expected owner-only access',
            }
    ensure_parent(signature_path)
    result = run_command([
        'openssl', 'pkeyutl', '-sign', '-inkey', str(key_path), '-rawin',
        '-in', str(snapshot_path), '-out', str(signature_path),
    ], timeout=15)
    if result.get('returncode') == 0:
        try:
            os.chmod(signature_path, 0o640)
        except OSError:
            pass
        return {'signed': True, 'signature': str(signature_path), 'signature_sha256': file_digest(signature_path).get('sha256')}
    return {'signed': False, 'reason': 'openssl signing failed', 'openssl': result}


def write_public_report(snapshot: Dict[str, Any], report_path: Path) -> None:
    ensure_parent(report_path)
    lines = [
        f"created_utc={snapshot['created_utc']}",
        f"snapshot_sha256={snapshot['snapshot_sha256']}",
        f"nft_table_present={snapshot['nftables'].get('table_present')}",
        f"guard_files={len(snapshot['guard_files'])}",
        f"audit_gate_decision={snapshot.get('ids_audit_gate', {}).get('decision', 'unknown')}",
        f"host={snapshot['host'].get('hostname', 'unknown')}",
    ]
    report_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    try:
        os.chmod(report_path, 0o640)
    except OSError:
        pass


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Create a local host/VM communication policy attestation snapshot.')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT), help='JSON snapshot path')
    parser.add_argument('--signature', default=str(DEFAULT_SIGNATURE), help='signature output path')
    parser.add_argument('--key', default=str(DEFAULT_KEY), help='optional local private key for OpenSSL pkeyutl signing')
    parser.add_argument('--report', default=str(DEFAULT_PUBLIC_REPORT), help='compact report path')
    parser.add_argument('--ids-audit', default=str(DEFAULT_IDS_AUDIT), help='NN IDS model audit JSON path')
    parser.add_argument('--ids-gate', default=str(DEFAULT_IDS_GATE), help='NN IDS audit gate JSON path')
    parser.add_argument('--extra-file', action='append', default=[], help='additional defensive config file to hash')
    parser.add_argument('--no-sign', action='store_true', help='skip optional signing even if a key exists')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    output = Path(args.output)
    snapshot = build_snapshot(args)
    ensure_parent(output)
    output.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        os.chmod(output, 0o640)
    except OSError:
        pass

    sign_result = {'signed': False, 'reason': 'signing disabled by --no-sign'}
    if not args.no_sign:
        sign_result = maybe_sign(output, Path(args.signature), Path(args.key))
    snapshot['signature'] = sign_result
    output.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_public_report(snapshot, Path(args.report))
    print(json.dumps({
        'output': str(output),
        'snapshot_sha256': snapshot['snapshot_sha256'],
        'signed': sign_result.get('signed', False),
        'report': args.report,
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
