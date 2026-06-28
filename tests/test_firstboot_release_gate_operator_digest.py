#!/usr/bin/env python3
# MINC - Tests for firstboot release-gate operator digest.
# Defensive validation only: verifies aggregate privacy-safe release handoff behavior.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'firstboot_release_gate_operator_digest.py'


def write_status(path: Path, *, ok: bool = True, decision: str = 'approved', release_gate: str = 'pass') -> None:
    path.write_text(
        json.dumps(
            {
                'component': 'firstboot_release_gate_status',
                'ok': ok,
                'decision': decision,
                'release_gate': release_gate,
                'source_created_utc': '2026-06-27T18:00:00Z',
                'blocker_count': 0 if ok else 1,
                'stale_or_skewed_count': 0,
                'validation_blockers': [] if ok else ['source_deferred'],
            }
        ),
        encoding='utf-8',
    )


def write_bundle(path: Path, *, ok: bool = True, decision: str = 'approved', release_gate: str = 'pass') -> None:
    path.write_text(
        json.dumps(
            {
                'component': 'firstboot_release_gate_bundle_manifest',
                'ok': ok,
                'decision': decision,
                'release_gate': release_gate,
                'created_utc': '2026-06-27T18:01:00Z',
                'blockers': [] if ok else ['status_not_passing'],
                'artifacts': [
                    {'name': 'firstboot_release_gate_json', 'required': True, 'exists': True, 'sha256': 'a' * 64},
                    {'name': 'firstboot_release_gate_markdown', 'required': True, 'exists': True, 'sha256': 'b' * 64},
                    {'name': 'firstboot_release_gate_summary', 'required': True, 'exists': True, 'sha256': 'c' * 64},
                    {'name': 'firstboot_release_gate_status_json', 'required': True, 'exists': True, 'sha256': 'd' * 64},
                ],
            }
        ),
        encoding='utf-8',
    )


def test_operator_digest_approved_json(tmp_path: Path) -> None:
    status = tmp_path / 'status.json'
    bundle = tmp_path / 'bundle.json'
    output = tmp_path / 'digest.json'
    write_status(status)
    write_bundle(bundle)

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            '--status-json',
            str(status),
            '--bundle-json',
            str(bundle),
            '--output',
            str(output),
            '--require-pass',
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    cli_summary = json.loads(result.stdout)
    assert cli_summary == {'decision': 'approved', 'format': 'json', 'ok': True, 'output': str(output)}
    digest = json.loads(output.read_text(encoding='utf-8'))
    assert digest['component'] == 'firstboot_release_gate_operator_digest'
    assert digest['release_gate'] == 'pass'
    assert digest['blockers'] == []
    assert digest['source_summary']['bundle_artifact_counts']['required'] == 4
    assert digest['source_summary']['bundle_artifact_counts']['hashed'] == 4
    assert 'ready for operator review' in digest['manager_summary']
    assert 'raw logs' in digest['privacy_exclusions']
    assert 'credentials' in digest['privacy_exclusions']
    assert 'model binaries' in digest['privacy_exclusions']
    assert 'read-only operator digest' in digest['safe_default']


def test_operator_digest_deferred_markdown(tmp_path: Path) -> None:
    status = tmp_path / 'status.json'
    bundle = tmp_path / 'bundle.json'
    output = tmp_path / 'digest.md'
    write_status(status, ok=False, decision='deferred', release_gate='stop')
    write_bundle(bundle, ok=False, decision='deferred', release_gate='stop')

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            '--status-json',
            str(status),
            '--bundle-json',
            str(bundle),
            '--output',
            str(output),
            '--format',
            'markdown',
            '--require-pass',
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 7
    rendered = output.read_text(encoding='utf-8')
    assert '# Firstboot release-gate operator digest' in rendered
    assert '- Decision: `deferred`' in rendered
    assert '- Release gate: `stop`' in rendered
    assert '- `status_not_passing`' in rendered
    assert '- `bundle_not_passing`' in rendered
    assert '- `status_validation_blockers_present`' in rendered
    assert '- `bundle_blockers_present`' in rendered
    assert 'Regenerate missing or malformed aggregate release-gate artifacts' not in rendered
    assert 'Review release-gate blockers and defer promotion' in rendered
    assert 'Privacy exclusions:' in rendered
    assert 'delete the generated operator digest' in rendered


def test_operator_digest_blocks_mismatched_sources(tmp_path: Path) -> None:
    status = tmp_path / 'status.json'
    bundle = tmp_path / 'bundle.json'
    output = tmp_path / 'digest.json'
    write_status(status, ok=True, decision='approved', release_gate='pass')
    write_bundle(bundle, ok=True, decision='deferred', release_gate='stop')

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            '--status-json',
            str(status),
            '--bundle-json',
            str(bundle),
            '--output',
            str(output),
            '--require-pass',
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 7
    digest = json.loads(output.read_text(encoding='utf-8'))
    assert digest['decision'] == 'deferred'
    assert 'decision_mismatch_between_status_and_bundle' in digest['blockers']
    assert 'release_gate_mismatch_between_status_and_bundle' in digest['blockers']
    assert 'Refresh status and bundle artifacts from the same firstboot release-gate run before promotion.' in digest['handoff_checklist']
