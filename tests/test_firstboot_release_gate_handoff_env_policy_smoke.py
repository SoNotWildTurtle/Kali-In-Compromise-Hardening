#!/usr/bin/env python3
# MINC - Tests for passive firstboot release-gate handoff env-policy smoke validator.
# Defensive validation only: no live system state is changed.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def write_env_policy_summary(path: Path, overrides: dict[str, str] | None = None) -> None:
    values = {
        'FIRSTBOOT_HANDOFF_ENV_POLICY_OK': '1',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_DECISION': 'approved',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_RELEASE_GATE': 'pass',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_COMPONENT': 'firstboot_release_gate_handoff_env_policy',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_CREATED_UTC': '2026-06-28T09:05:00Z',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_DECISION': 'approved',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_RELEASE_GATE': 'pass',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_PRIVACY_SCOPE': 'aggregate_release_gate_handoff_status_reader_only',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_BLOCKER_COUNT': '0',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_BLOCKERS': 'none',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_TOTAL_ARTIFACTS': '4',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_PRIVACY_SCOPE': 'aggregate_release_gate_handoff_env_policy_only',
        'FIRSTBOOT_HANDOFF_ENV_POLICY_SAFE_DEFAULT': 'read-only summary evidence validator; no live system state was changed',
    }
    if overrides:
        values.update(overrides)
    path.write_text(''.join(f"{key}='{value}'\n" for key, value in values.items()), encoding='utf-8')


def test_env_policy_smoke_approves_passing_summary(tmp_path: Path) -> None:
    summary = tmp_path / 'env_policy.summary.env'
    write_env_policy_summary(summary)

    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_env_policy_smoke.py',
            '--input',
            str(summary),
            '--require-pass',
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'decision=approved' in completed.stdout
    assert 'release_gate=pass' in completed.stdout
    assert 'blockers=none' in completed.stdout


def test_env_policy_smoke_fails_closed_on_privacy_mismatch(tmp_path: Path) -> None:
    summary = tmp_path / 'env_policy.summary.env'
    output = tmp_path / 'smoke.json'
    write_env_policy_summary(summary, {'FIRSTBOOT_HANDOFF_ENV_POLICY_PRIVACY_SCOPE': 'raw_logs_allowed'})

    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_env_policy_smoke.py',
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
    assert 'privacy_scope_mismatch:raw_logs_allowed' in payload['blockers']


def test_env_policy_smoke_writes_summary_sidecar(tmp_path: Path) -> None:
    summary = tmp_path / 'env_policy.summary.env'
    output = tmp_path / 'smoke.json'
    sidecar = tmp_path / 'smoke.summary.env'
    write_env_policy_summary(summary)

    subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_env_policy_smoke.py',
            '--input',
            str(summary),
            '--format',
            'json',
            '--output',
            str(output),
            '--summary',
            str(sidecar),
            '--require-pass',
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(output.read_text(encoding='utf-8'))
    env = sidecar.read_text(encoding='utf-8')
    assert payload['decision'] == 'approved'
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_OK='1'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_DECISION='approved'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_RELEASE_GATE='pass'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKER_COUNT='0'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKERS='none'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_TOTAL_ARTIFACTS='4'" in env
    assert 'raw logs' not in env.lower()
    assert 'packet' not in env.lower()
    assert 'dataset' not in env.lower()


def test_env_policy_smoke_writes_deferred_summary_sidecar(tmp_path: Path) -> None:
    summary = tmp_path / 'env_policy.summary.env'
    sidecar = tmp_path / 'smoke.summary.env'
    write_env_policy_summary(
        summary,
        {
            'FIRSTBOOT_HANDOFF_ENV_POLICY_OK': '0',
            'FIRSTBOOT_HANDOFF_ENV_POLICY_DECISION': 'deferred',
            'FIRSTBOOT_HANDOFF_ENV_POLICY_RELEASE_GATE': 'stop',
            'FIRSTBOOT_HANDOFF_ENV_POLICY_BLOCKER_COUNT': '1',
            'FIRSTBOOT_HANDOFF_ENV_POLICY_BLOCKERS': 'upstream_policy_blocker',
        },
    )

    completed = subprocess.run(
        [
            sys.executable,
            'firstboot_release_gate_handoff_env_policy_smoke.py',
            '--input',
            str(summary),
            '--summary',
            str(sidecar),
            '--require-pass',
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    env = sidecar.read_text(encoding='utf-8')
    assert completed.returncode == 10
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_OK='0'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_DECISION='deferred'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_RELEASE_GATE='stop'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKER_COUNT='1'" in env
    assert "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKERS='upstream_policy_blocker'" in env


def test_env_policy_smoke_static_packaging_service_and_docs_contracts() -> None:
    subprocess.run([sys.executable, '-m', 'py_compile', 'firstboot_release_gate_handoff_env_policy_smoke.py'], check=True)
    docs = Path('docs/firstboot_release_gate_handoff_env_policy_smoke.md').read_text(encoding='utf-8')
    changelog = Path('docs/firstboot_release_gate_handoff_env_policy_smoke_changelog.md').read_text(encoding='utf-8')
    build = Path('build_custom_iso.sh').read_text(encoding='utf-8')
    service = Path('firstboot_release_gate.service').read_text(encoding='utf-8')
    assert '--require-pass' in docs
    assert '--summary' in docs
    assert 'summary sidecar' in docs.lower()
    assert 'FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_' in docs
    assert 'summary.env' in docs
    assert 'rollback' in docs.lower()
    assert 'firstboot_release_gate_handoff_env_policy_smoke.py' in changelog
    assert 'summary' in changelog.lower()
    assert 'rollback' in changelog.lower()
    assert 'firstboot_release_gate_handoff_env_policy_smoke.py' in build
    assert 'firstboot_release_gate.handoff_env_policy.summary.env' in service
    assert 'firstboot_release_gate.handoff_env_policy_smoke.json' in service
    assert 'firstboot_release_gate.handoff_env_policy_smoke.md' in service
    assert 'firstboot_release_gate.handoff_env_policy_smoke.summary.env' in service
    assert '--summary /var/log/firstboot_release_gate.handoff_env_policy_smoke.summary.env' in service
    assert '--format markdown' in service
