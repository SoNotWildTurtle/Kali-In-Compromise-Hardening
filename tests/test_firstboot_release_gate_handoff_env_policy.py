#!/usr/bin/env python3
# MINC - Tests for passive firstboot release-gate handoff env policy validator.
# Defensive validation only: no live system state is changed.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def write_summary(path: Path, overrides: dict[str, str] | None = None) -> None:
    values = {
        'FIRSTBOOT_HANDOFF_STATUS_READER_OK': '1',
        'FIRSTBOOT_HANDOFF_STATUS_READER_DECISION': 'approved',
        'FIRSTBOOT_HANDOFF_STATUS_READER_RELEASE_GATE': 'pass',
        'FIRSTBOOT_HANDOFF_STATUS_READER_SOURCE_COMPONENT': 'firstboot_release_gate_handoff_summary_smoke',
        'FIRSTBOOT_HANDOFF_STATUS_READER_SOURCE_CREATED_UTC': '2026-06-28T08:10:00Z',
        'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKER_COUNT': '0',
        'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKERS': 'none',
        'FIRSTBOOT_HANDOFF_STATUS_READER_FRESH_REQUIRED_VERIFIED': '4',
        'FIRSTBOOT_HANDOFF_STATUS_READER_REQUIRED_VERIFIED': '4',
        'FIRSTBOOT_HANDOFF_STATUS_READER_TOTAL_ARTIFACTS': '4',
        'FIRSTBOOT_HANDOFF_STATUS_READER_SOURCE_BLOCKER_COUNT': '0',
        'FIRSTBOOT_HANDOFF_STATUS_READER_PRIVACY_SCOPE': 'aggregate_release_gate_handoff_status_reader_only',
    }
    if overrides:
        values.update(overrides)
    path.write_text(''.join(f"{key}='{value}'\n" for key, value in values.items()), encoding='utf-8')


def test_env_policy_approves_passing_summary(tmp_path: Path) -> None:
    summary = tmp_path / 'status.summary.env'
    write_summary(summary)

    completed = subprocess.run(
        [sys.executable, 'firstboot_release_gate_handoff_env_policy.py', '--input', str(summary), '--require-pass'],
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'decision=approved' in completed.stdout
    assert 'release_gate=pass' in completed.stdout
    assert 'blockers=none' in completed.stdout


def test_env_policy_fails_closed_on_mismatched_summary(tmp_path: Path) -> None:
    summary = tmp_path / 'status.summary.env'
    output = tmp_path / 'policy.json'
    write_summary(
        summary,
        {
            'FIRSTBOOT_HANDOFF_STATUS_READER_OK': '1',
            'FIRSTBOOT_HANDOFF_STATUS_READER_RELEASE_GATE': 'stop',
        },
    )

    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_env_policy.py',
            '--input',
            str(summary),
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
    assert 'ok_release_gate_mismatch' in payload['blockers']


def test_env_policy_fails_closed_on_blocker_count_mismatch(tmp_path: Path) -> None:
    summary = tmp_path / 'status.summary.env'
    output = tmp_path / 'policy.json'
    write_summary(summary, {'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKER_COUNT': '2', 'FIRSTBOOT_HANDOFF_STATUS_READER_BLOCKERS': 'none'})

    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_env_policy.py',
            '--input',
            str(summary),
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
    assert 'blocker_count_positive_but_blockers_missing' in payload['blockers']


def test_env_policy_markdown_includes_privacy_and_rollback(tmp_path: Path) -> None:
    summary = tmp_path / 'status.summary.env'
    output = tmp_path / 'policy.md'
    write_summary(summary)

    subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_env_policy.py',
            '--input',
            str(summary),
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
    assert '# Firstboot release-gate handoff env policy' in markdown
    assert 'Aggregate source values' in markdown
    assert 'Privacy exclusions' in markdown
    assert 'raw telemetry' in markdown
    assert 'Rollback' in markdown


def test_env_policy_static_packaging_service_and_docs_contracts() -> None:
    subprocess.run([sys.executable, '-m', 'py_compile', 'firstboot_release_gate_handoff_env_policy.py'], check=True)
    docs = Path('docs/firstboot_release_gate_handoff_env_policy.md').read_text(encoding='utf-8')
    changelog = Path('docs/firstboot_release_gate_handoff_env_policy_changelog.md').read_text(encoding='utf-8')
    build = Path('build_custom_iso.sh').read_text(encoding='utf-8')
    service = Path('firstboot_release_gate.service').read_text(encoding='utf-8')
    assert '--require-pass' in docs
    assert 'aggregate-only' in docs
    assert 'summary.env' in docs
    assert 'rollback' in docs.lower()
    assert 'firstboot_release_gate_handoff_env_policy.py' in changelog
    assert 'firstboot_release_gate_handoff_env_policy.py' in build
    assert 'firstboot_release_gate.handoff_status_reader.summary.env' in service
    assert 'firstboot_release_gate.handoff_env_policy.json' in service
    assert 'firstboot_release_gate.handoff_env_policy.md' in service
    assert '--format markdown' in service
