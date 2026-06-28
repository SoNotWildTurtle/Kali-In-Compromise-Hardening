#!/usr/bin/env python3
# MINC - Tests for passive firstboot release-gate handoff status reader.
# Defensive validation only: no live system state is changed.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def write_smoke(path: Path, overrides: dict[str, object] | None = None) -> None:
    payload: dict[str, object] = {
        'schema_version': 1,
        'component': 'firstboot_release_gate_handoff_summary_smoke',
        'created_utc': '2026-06-28T08:10:00Z',
        'ok': True,
        'decision': 'approved',
        'release_gate': 'pass',
        'source_component': 'firstboot_release_gate_handoff_freshness',
        'source_created_utc': '2026-06-28T08:09:00Z',
        'source_values': {
            'fresh_required_verified': 4,
            'required_verified': 4,
            'total_artifacts': 4,
            'blocker_count': 0,
        },
        'blockers': [],
        'operator_summary': 'approved',
        'privacy_scope': 'aggregate_release_gate_handoff_summary_smoke_only',
    }
    if overrides:
        payload.update(overrides)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def test_status_reader_outputs_compact_text_for_passing_smoke(tmp_path: Path) -> None:
    smoke = tmp_path / 'smoke.json'
    write_smoke(smoke)

    completed = subprocess.run(
        [sys.executable, 'firstboot_release_gate_handoff_status_reader.py', '--input', str(smoke), '--require-pass'],
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'decision=approved' in completed.stdout
    assert 'release_gate=pass' in completed.stdout
    assert 'blockers=none' in completed.stdout
    assert 'source_component=firstboot_release_gate_handoff_summary_smoke' in completed.stdout


def test_status_reader_fails_closed_on_deferred_smoke(tmp_path: Path) -> None:
    smoke = tmp_path / 'smoke.json'
    output = tmp_path / 'status.json'
    write_smoke(
        smoke,
        {
            'ok': False,
            'decision': 'deferred',
            'release_gate': 'stop',
            'blockers': ['stale_verified_artifact:firstboot_release_gate.md'],
        },
    )

    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_status_reader.py',
            '--input',
            str(smoke),
            '--format',
            'json',
            '--output',
            str(output),
            '--require-pass',
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(output.read_text(encoding='utf-8'))
    assert completed.returncode == 10
    assert payload['decision'] == 'deferred'
    assert payload['release_gate'] == 'stop'
    assert 'stale_verified_artifact:firstboot_release_gate.md' in payload['blockers']
    assert 'override' in ' '.join(payload['operator_next_steps'])


def test_status_reader_fails_closed_on_contradictory_passing_smoke(tmp_path: Path) -> None:
    smoke = tmp_path / 'smoke.json'
    output = tmp_path / 'status.json'
    write_smoke(smoke, {'ok': True, 'decision': 'approved', 'release_gate': 'stop'})

    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_status_reader.py',
            '--input',
            str(smoke),
            '--format',
            'json',
            '--output',
            str(output),
            '--require-pass',
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(output.read_text(encoding='utf-8'))
    assert completed.returncode == 10
    assert 'ok_release_gate_mismatch' in payload['blockers']


def test_status_reader_markdown_includes_privacy_and_rollback(tmp_path: Path) -> None:
    smoke = tmp_path / 'smoke.json'
    output = tmp_path / 'status.md'
    write_smoke(smoke)

    subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_status_reader.py',
            '--input',
            str(smoke),
            '--format',
            'markdown',
            '--output',
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    markdown = output.read_text(encoding='utf-8')
    assert '# Firstboot release-gate handoff terminal status' in markdown
    assert 'Aggregate source values' in markdown
    assert 'Privacy exclusions' in markdown
    assert 'raw telemetry' in markdown
    assert 'Rollback' in markdown


def test_status_reader_static_packaging_and_docs_contracts() -> None:
    subprocess.run([sys.executable, '-m', 'py_compile', 'firstboot_release_gate_handoff_status_reader.py'], check=True)
    docs = Path('docs/firstboot_release_gate_handoff_status_reader.md').read_text(encoding='utf-8')
    changelog = Path('docs/firstboot_release_gate_handoff_status_reader_changelog.md').read_text(encoding='utf-8')
    build = Path('build_custom_iso.sh').read_text(encoding='utf-8')
    assert '--require-pass' in docs
    assert 'terminal' in docs.lower()
    assert 'aggregate-only' in docs
    assert 'rollback' in docs.lower()
    assert 'firstboot_release_gate_handoff_status_reader.py' in changelog
    assert 'firstboot_release_gate_handoff_status_reader.py' in build
