#!/usr/bin/env python3
# MINC - Tests for passive firstboot release-gate handoff freshness gating.
# Defensive validation only: no host, VM, service, firewall, model, dataset, or firstboot state is changed.

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def make_verification(tmp_path: Path) -> Path:
    artifact = tmp_path / 'status.json'
    write_json(artifact, {'component': 'firstboot_release_gate_status', 'ok': True, 'release_gate': 'pass'})
    verification = tmp_path / 'firstboot_release_gate.handoff_verify.json'
    write_json(
        verification,
        {
            'artifacts': [
                {
                    'exists': True,
                    'label': 'status_json',
                    'path': str(artifact),
                    'required': True,
                    'verified': True,
                }
            ],
            'component': 'firstboot_release_gate_handoff_verify',
            'decision': 'approved',
            'ok': True,
            'privacy_scope': 'aggregate_release_gate_handoff_verification_only',
            'release_gate': 'pass',
            'schema_version': 1,
        },
    )
    return verification


def test_handoff_freshness_accepts_current_verified_evidence(tmp_path: Path) -> None:
    verification = make_verification(tmp_path)
    output = tmp_path / 'freshness.json'
    subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_freshness.py',
            '--input',
            str(verification),
            '--output',
            str(output),
            '--max-artifact-age-minutes',
            '60',
            '--require-fresh',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(output.read_text(encoding='utf-8'))
    assert payload['component'] == 'firstboot_release_gate_handoff_freshness'
    assert payload['ok'] is True
    assert payload['release_gate'] == 'pass'
    assert payload['artifact_counts']['fresh_required_verified'] == 1
    assert payload['privacy_scope'] == 'aggregate_release_gate_handoff_freshness_only'


def test_handoff_freshness_fails_closed_on_stale_verified_artifact(tmp_path: Path) -> None:
    verification = make_verification(tmp_path)
    stale_artifact = tmp_path / 'status.json'
    stale_time = time.time() - 3 * 3600
    os.utime(stale_artifact, (stale_time, stale_time))
    output = tmp_path / 'freshness.json'
    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_freshness.py',
            '--input',
            str(verification),
            '--output',
            str(output),
            '--max-artifact-age-minutes',
            '1',
            '--require-fresh',
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(output.read_text(encoding='utf-8'))
    assert completed.returncode == 10
    assert payload['ok'] is False
    assert payload['release_gate'] == 'stop'
    assert 'stale_verified_artifact:status_json' in payload['blockers']


def test_handoff_freshness_markdown_documents_policy_privacy_and_rollback(tmp_path: Path) -> None:
    verification = make_verification(tmp_path)
    output = tmp_path / 'freshness.md'
    subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_freshness.py',
            '--input',
            str(verification),
            '--output',
            str(output),
            '--format',
            'markdown',
            '--max-artifact-age-minutes',
            '60',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    markdown = output.read_text(encoding='utf-8')
    assert '# Firstboot release-gate handoff freshness' in markdown
    assert 'Max artifact age' in markdown
    assert 'Privacy exclusions' in markdown
    assert 'Rollback' in markdown
    assert 'raw telemetry' in markdown


def test_handoff_freshness_static_documentation_contract() -> None:
    subprocess.run([sys.executable, '-m', 'py_compile', 'firstboot_release_gate_handoff_freshness.py'], check=True)
    docs = Path('docs/firstboot_release_gate_handoff_freshness.md').read_text(encoding='utf-8')
    changelog = Path('docs/firstboot_release_gate_handoff_freshness_changelog.md').read_text(encoding='utf-8')
    assert '--max-artifact-age-minutes' in docs
    assert '--require-fresh' in docs
    assert 'rollback' in docs.lower()
    assert 'aggregate-only' in docs
    assert 'firstboot_release_gate_handoff_freshness.py' in changelog
