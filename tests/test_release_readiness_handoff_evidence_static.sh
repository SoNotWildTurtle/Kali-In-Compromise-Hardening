#!/usr/bin/env bash
# MINC - Static coverage for release-readiness handoff documentation.
# Defensive validation only: confirms passive reviewer evidence guidance stays present.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
import pathlib
import sys

paths = {
    'guide': pathlib.Path('docs/release_readiness_handoff_evidence.md'),
    'changelog': pathlib.Path('changelog.d/release_readiness_handoff_evidence.md'),
    'static_workflow': pathlib.Path('.github/workflows/static-security-checks.yml'),
    'restore_workflow': pathlib.Path('.github/workflows/restore-executor-release-gate.yml'),
}
errors = []

for label, path in paths.items():
    if not path.exists():
        errors.append(f'missing {label} file: {path}')

if paths['guide'].exists():
    guide = paths['guide'].read_text(encoding='utf-8')
    for token in [
        'Release Readiness Handoff Evidence',
        'Static Security Checks',
        'Restore Executor Release Gate',
        'restore-executor-release-evidence',
        'NN IDS triage schemas',
        'GITHUB_STEP_SUMMARY',
        'bash tests/run_static_security_checks.sh',
        'python3 host_vm_restore_executor_wiring_check.py',
        'rollback',
        'does not add a new workflow',
    ]:
        if token not in guide:
            errors.append(f'release handoff guide missing token {token}')

if paths['changelog'].exists():
    changelog = paths['changelog'].read_text(encoding='utf-8')
    for token in [
        'docs/release_readiness_handoff_evidence.md',
        'Static Security Checks',
        'Restore Executor Release Gate',
        'restore-executor-release-evidence',
        'NN IDS triage evidence',
        'GITHUB_STEP_SUMMARY',
        'rollback',
        'Documentation and static guardrail scope only',
    ]:
        if token not in changelog:
            errors.append(f'release handoff changelog missing token {token}')

if paths['static_workflow'].exists():
    static_workflow = paths['static_workflow'].read_text(encoding='utf-8')
    for token in [
        'Static Security Checks',
        'GITHUB_STEP_SUMMARY',
        'bash tests/run_static_security_checks.sh',
    ]:
        if token not in static_workflow:
            errors.append(f'static workflow missing handoff anchor {token}')

if paths['restore_workflow'].exists():
    restore_workflow = paths['restore_workflow'].read_text(encoding='utf-8')
    for token in [
        'Restore Executor Release Gate',
        'GITHUB_STEP_SUMMARY',
        'restore-executor-release-evidence',
    ]:
        if token not in restore_workflow:
            errors.append(f'restore workflow missing handoff anchor {token}')

if errors:
    for error in errors:
        print(f'[release-handoff-static][FAIL] {error}', file=sys.stderr)
    sys.exit(1)

print('[release-handoff-static] release readiness handoff evidence coverage passed')
PY
