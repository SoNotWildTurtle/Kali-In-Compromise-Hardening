#!/usr/bin/env python3
# MINC - Tests for firstboot release-gate bundle manifest Markdown output.
# Defensive validation only: verifies privacy-safe operator handoff rendering.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'firstboot_release_gate_bundle_manifest.py'


def test_markdown_output_for_passing_bundle(tmp_path: Path) -> None:
    gate_json = tmp_path / 'firstboot_release_gate.json'
    gate_md = tmp_path / 'firstboot_release_gate.md'
    summary = tmp_path / 'firstboot_release_gate.summary.env'
    status_json = tmp_path / 'firstboot_release_gate.status.json'
    output = tmp_path / 'firstboot_release_gate.bundle_manifest.md'

    gate_json.write_text('{"decision":"approved"}\n', encoding='utf-8')
    gate_md.write_text('# Firstboot release gate\n', encoding='utf-8')
    summary.write_text('FIRSTBOOT_RELEASE_GATE_DECISION="approved"\n', encoding='utf-8')
    status_json.write_text(
        json.dumps(
            {
                'component': 'firstboot_release_gate_status',
                'ok': True,
                'decision': 'approved',
                'release_gate': 'pass',
                'source_created_utc': '2026-06-27T16:00:00Z',
                'artifact_count': 4,
                'blocker_count': 0,
                'stale_or_skewed_count': 0,
                'validation_blockers': [],
            }
        ),
        encoding='utf-8',
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            '--gate-json',
            str(gate_json),
            '--gate-markdown',
            str(gate_md),
            '--summary',
            str(summary),
            '--status-json',
            str(status_json),
            '--output',
            str(output),
            '--format',
            'markdown',
            '--require-pass',
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    cli_summary = json.loads(result.stdout)
    assert cli_summary == {'decision': 'approved', 'format': 'markdown', 'ok': True, 'output': str(output)}

    rendered = output.read_text(encoding='utf-8')
    assert '# Firstboot release-gate bundle manifest' in rendered
    assert '- Decision: `approved`' in rendered
    assert '- Release gate: `pass`' in rendered
    assert '| firstboot_release_gate_json | true | true |' in rendered
    assert '## Blockers\n\n- None' in rendered
    assert 'Privacy exclusions:' in rendered
    assert 'raw logs' in rendered
    assert 'credentials' in rendered
    assert 'model binaries' in rendered
    assert 'Safe default: read-only manifest builder' in rendered
    assert 'delete the generated bundle manifest' in rendered


def test_markdown_output_preserves_require_pass_failure(tmp_path: Path) -> None:
    gate_json = tmp_path / 'firstboot_release_gate.json'
    gate_md = tmp_path / 'firstboot_release_gate.md'
    summary = tmp_path / 'firstboot_release_gate.summary.env'
    status_json = tmp_path / 'firstboot_release_gate.status.json'
    output = tmp_path / 'firstboot_release_gate.bundle_manifest.md'

    gate_json.write_text('{"decision":"deferred"}\n', encoding='utf-8')
    gate_md.write_text('# Firstboot release gate\n', encoding='utf-8')
    summary.write_text('FIRSTBOOT_RELEASE_GATE_DECISION="deferred"\n', encoding='utf-8')
    status_json.write_text(
        json.dumps(
            {
                'component': 'firstboot_release_gate_status',
                'ok': False,
                'decision': 'deferred',
                'release_gate': 'stop',
                'source_created_utc': '2026-06-27T16:00:00Z',
                'artifact_count': 4,
                'blocker_count': 1,
                'stale_or_skewed_count': 0,
                'validation_blockers': ['release_gate_stop'],
            }
        ),
        encoding='utf-8',
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            '--gate-json',
            str(gate_json),
            '--gate-markdown',
            str(gate_md),
            '--summary',
            str(summary),
            '--status-json',
            str(status_json),
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
    assert '- Decision: `deferred`' in rendered
    assert '- Release gate: `stop`' in rendered
    assert '- `status_not_passing`' in rendered
    assert '- `status_release_gate:stop`' in rendered
    assert '- `status_validation_blockers_present`' in rendered
    assert 'Review firstboot release-gate status blockers before promotion.' in rendered
