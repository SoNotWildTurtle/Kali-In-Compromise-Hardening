#!/usr/bin/env python3
# MINC - Tests for passive firstboot release-gate handoff verification.
# Defensive validation only: no host, VM, service, firewall, model, dataset, or firstboot state is changed.

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_bundle(tmp_path: Path) -> Path:
    artifacts = []
    for label, component in (
        ('status_json', 'firstboot_release_gate_status'),
        ('bundle_manifest_json', 'firstboot_release_gate_bundle_manifest'),
        ('operator_digest_json', 'firstboot_release_gate_operator_digest'),
    ):
        path = tmp_path / f'{label}.json'
        write_json(path, {'component': component, 'decision': 'approved', 'ok': True, 'release_gate': 'pass'})
        artifacts.append(
            {
                'exists': True,
                'format': 'json',
                'label': label,
                'path': f'/var/log/{path.name}',
                'required': True,
                'sha256': digest(path),
                'size_bytes': path.stat().st_size,
            }
        )
    index = tmp_path / 'firstboot_release_gate.handoff_index.json'
    write_json(
        index,
        {
            'artifacts': artifacts,
            'component': 'firstboot_release_gate_handoff_index',
            'decision': 'approved',
            'ok': True,
            'privacy_scope': 'aggregate_release_gate_handoff_index_only',
            'release_gate': 'pass',
            'schema_version': 1,
        },
    )
    return index


def test_handoff_verify_accepts_matching_hashes(tmp_path: Path) -> None:
    index = make_bundle(tmp_path)
    output = tmp_path / 'verify.json'
    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_verify.py',
            '--index',
            str(index),
            '--artifact-root',
            str(tmp_path),
            '--output',
            str(output),
            '--require-verified',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(output.read_text(encoding='utf-8'))
    assert payload['component'] == 'firstboot_release_gate_handoff_verify'
    assert payload['ok'] is True
    assert payload['release_gate'] == 'pass'
    assert payload['artifact_counts']['required_verified'] == 3
    assert 'privacy-safe handoff bundle' not in completed.stdout


def test_handoff_verify_fails_closed_on_hash_mismatch(tmp_path: Path) -> None:
    index = make_bundle(tmp_path)
    (tmp_path / 'status_json.json').write_text('{"component":"firstboot_release_gate_status","ok":true}\n', encoding='utf-8')
    output = tmp_path / 'verify.json'
    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_verify.py',
            '--index',
            str(index),
            '--artifact-root',
            str(tmp_path),
            '--output',
            str(output),
            '--require-verified',
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(output.read_text(encoding='utf-8'))
    assert completed.returncode == 9
    assert payload['ok'] is False
    assert payload['release_gate'] == 'stop'
    assert 'sha256_mismatch:status_json' in payload['blockers']


def test_handoff_verify_markdown_documents_privacy_and_rollback(tmp_path: Path) -> None:
    index = make_bundle(tmp_path)
    output = tmp_path / 'verify.md'
    subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_verify.py',
            '--index',
            str(index),
            '--artifact-root',
            str(tmp_path),
            '--output',
            str(output),
            '--format',
            'markdown',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    markdown = output.read_text(encoding='utf-8')
    assert '# Firstboot release-gate handoff verification' in markdown
    assert 'Privacy exclusions' in markdown
    assert 'Rollback' in markdown
    assert 'raw telemetry' in markdown


def test_handoff_verify_static_packaging_contract() -> None:
    subprocess.run([sys.executable, '-m', 'py_compile', 'firstboot_release_gate_handoff_verify.py'], check=True)
    readme = Path('README.md').read_text(encoding='utf-8')
    changelog = Path('CHANGELOG.md').read_text(encoding='utf-8')
    docs = Path('docs/firstboot_release_gate_handoff_verify.md').read_text(encoding='utf-8')
    assert 'firstboot_release_gate_handoff_verify.py' in readme
    assert 'firstboot_release_gate_handoff_verify.py' in changelog
    assert '--require-verified' in docs
    assert 'rollback' in docs.lower()
