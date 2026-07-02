#!/usr/bin/env bash
# MINC - Repo-wide static validation for defensive Kali hardening modules.
# This test is defensive only: it verifies syntax, packaging coverage, and service wiring.
# Restore executor release gate token: host_vm_policy_restore_execute_static.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0

note() {
    printf '[static-check] %s\n' "$*"
}

fail() {
    printf '[static-check][FAIL] %s\n' "$*" >&2
    failures=$((failures + 1))
}

require_file() {
    local file="$1"
    [[ -f "$file" ]] || fail "missing required file: $file"
}

note "checking required top-level orchestrators"
require_file build_custom_iso.sh
require_file firstboot.sh
require_file README.md

note "checking shell syntax"
while IFS= read -r -d '' script; do
    bash -n "$script" || fail "bash syntax failed: $script"
done < <(find . -maxdepth 3 -type f \( -name '*.sh' -o -path './tests/*.sh' \) -print0)

note "checking Python syntax"
while IFS= read -r -d '' pyfile; do
    python3 -m py_compile "$pyfile" || fail "python compile failed: $pyfile"
done < <(find . -maxdepth 2 -type f -name '*.py' -print0)

note "checking ISO packaging coverage for systemd units and executable modules"
python3 - <<'PY'
import pathlib
import re
import sys

root = pathlib.Path('.')
build = (root / 'build_custom_iso.sh').read_text(encoding='utf-8')
firstboot = (root / 'firstboot.sh').read_text(encoding='utf-8')
smoke = (root / 'vm_smoke_check.sh').read_text(encoding='utf-8')
errors = []

# All repository systemd units should be explicitly packaged unless generated at build time.
for unit in sorted(list(root.glob('*.service')) + list(root.glob('*.timer'))):
    name = unit.name
    if name == 'firstboot.service':
        continue
    if f'"{name}"' not in build and f"'{name}'" not in build:
        errors.append(f'{name} exists but is not listed in build_custom_iso.sh')

# Every packaged module reference should point at a real file, except the firstboot.service
# generated inside build_custom_iso.sh.
packaged = set(re.findall(r'"([A-Za-z0-9_.-]+\.(?:sh|py|service|timer|ps1|conf|cfg|logrotate))"', build))
for name in sorted(packaged):
    if name == 'firstboot.service':
        continue
    if not (root / name).exists():
        errors.append(f'build_custom_iso.sh packages missing file {name}')

# firstboot should only enable/start units that exist in the repo or are generated at ISO build time.
unit_refs = set(re.findall(r'\^([A-Za-z0-9_.@-]+\.(?:service|timer))', firstboot))
unit_refs.update(re.findall(r'systemctl\s+(?:enable --now|enable|start|restart)\s+([A-Za-z0-9_.@-]+\.(?:service|timer))', firstboot))
for unit_name in sorted(unit_refs):
    if unit_name == 'firstboot.service':
        continue
    if not (root / unit_name).exists():
        errors.append(f'firstboot.sh references missing unit {unit_name}')

# Make sure the critical NN audit/attestation/verification chain remains wired in order.
required_order = [
    'nn_ids_model_audit.timer',
    'nn_ids_model_audit.py',
    'nn_ids_audit_gate.timer',
    'nn_ids_audit_gate.py',
    'host_vm_policy_attest.timer',
    'host_vm_policy_attest.py',
    'host_vm_policy_verify.timer',
    'host_vm_policy_verify.py --init-baseline',
    'host_vm_policy_verify.firstboot.log',
]
positions = []
for token in required_order:
    pos = firstboot.find(token)
    if pos == -1:
        errors.append(f'firstboot.sh missing audit/attestation/verification chain token {token}')
    positions.append(pos)
if all(pos >= 0 for pos in positions) and positions != sorted(positions):
    errors.append('firstboot.sh should run model audit, audit gate, policy attestation, then policy verification')

# Critical guardrails added by recent runs should remain present and covered.
for token in [
    'host_vm_comm_guard.sh',
    'host_vm_comm_guard.service',
    'host_vm_policy_attest.py',
    'host_vm_policy_attest.service',
    'host_vm_policy_attest.timer',
    'host_vm_policy_verify.py',
    'host_vm_policy_verify.service',
    'host_vm_policy_verify.timer',
    'host_vm_policy_restore_execute.py',
    'host_vm_policy_restore_execute.service',
    'tests/test_host_vm_policy_restore_execute_static.sh',
    'nn_ids_model_audit.py',
    'nn_ids_model_audit.service',
    'nn_ids_model_audit.timer',
    'nn_ids_audit_gate.py',
    'nn_ids_audit_gate.service',
    'nn_ids_audit_gate.timer',
    'nn_ids_triage_record_validate.sh',
    'nn_ids_triage_bundle_manifest.py',
    'tests/test_nn_ids_triage_record_validator_static.sh',
    'tests/test_nn_ids_triage_record_schema_static.sh',
    'tests/test_nn_ids_triage_bundle_manifest_static.sh',
    'docs/nn_ids_triage_record_validator.md',
    'schemas/nn_ids_triage_record.schema.json',
    'examples/nn_ids_triage_bundle_manifest.example.json',
    'changelog.d/nn_ids_triage_record_validator.md',
]:
    if token.startswith('tests/') or token.startswith('docs/') or token.startswith('schemas/') or token.startswith('examples/') or token.startswith('changelog.d/'):
        if not (root / token).exists():
            errors.append(f'missing critical evidence file {token}')
    elif token.endswith('.sh') and token == 'nn_ids_triage_record_validate.sh':
        if not (root / token).exists():
            errors.append(f'missing critical passive validator {token}')
        if f'"{token}"' not in build and f"'{token}'" not in build:
            errors.append(f'build_custom_iso.sh missing critical passive validator {token}')
    elif token.endswith('.py') and token == 'nn_ids_triage_bundle_manifest.py':
        if not (root / token).exists():
            errors.append(f'missing critical passive manifest helper {token}')
        if f'"{token}"' not in build and f"'{token}'" not in build:
            errors.append(f'build_custom_iso.sh missing critical passive manifest helper {token}')
    elif f'"{token}"' not in build and f"'{token}'" not in build:
        errors.append(f'build_custom_iso.sh missing critical module {token}')

# The restore executor must be smoke-check visible but never timer-driven.
for token in [
    '/usr/local/bin/host_vm_policy_restore_execute.py',
    'host_vm_policy_restore_execute.service',
    '/var/lib/host_vm_comm_guard/policy_restore_execute.json',
    '/var/log/host_vm_policy_restore_execute.report',
]:
    if token not in smoke:
        errors.append(f'vm_smoke_check.sh missing restore executor token {token}')
if (root / 'host_vm_policy_restore_execute.timer').exists():
    errors.append('manual restore executor must not have a timer file')
if 'host_vm_policy_restore_execute.timer' in build or 'host_vm_policy_restore_execute.timer' in firstboot:
    errors.append('manual restore executor timer must not be packaged or firstboot-wired')

if errors:
    for error in errors:
        print(f'[static-check][FAIL] {error}', file=sys.stderr)
    sys.exit(1)
print('[static-check] ISO, firstboot, smoke, and restore-executor wiring checks passed')
PY

note "checking workflow diagnostics coverage"
python3 - <<'PY'
import pathlib
import sys

workflow_path = pathlib.Path('.github/workflows/static-security-checks.yml')
doc_path = pathlib.Path('docs/static_workflow_diagnostics.md')
changelog_path = pathlib.Path('changelog.d/static_workflow_diagnostics.md')
errors = []

for path in [workflow_path, doc_path, changelog_path]:
    if not path.exists():
        errors.append(f'missing workflow diagnostics evidence file {path}')

if workflow_path.exists():
    workflow = workflow_path.read_text(encoding='utf-8')
    for token in [
        'concurrency:',
        'cancel-in-progress: true',
        'timeout-minutes: 10',
        'Write static diagnostics summary',
        'GITHUB_STEP_SUMMARY',
        'Run defensive static checks',
        'bash tests/run_static_security_checks.sh',
        'does not inspect live IDS, host, VM, hypervisor, packet, payload, firewall, restore, retraining, service, network, or telemetry state',
    ]:
        if token not in workflow:
            errors.append(f'static workflow missing diagnostics token {token}')

if doc_path.exists():
    doc = doc_path.read_text(encoding='utf-8')
    for token in [
        'Static Security Checks',
        'bash tests/run_static_security_checks.sh',
        'GITHUB_STEP_SUMMARY',
        'rollback',
        'diagnostics only',
    ]:
        if token not in doc:
            errors.append(f'static workflow diagnostics doc missing token {token}')

if changelog_path.exists():
    changelog = changelog_path.read_text(encoding='utf-8')
    for token in [
        'concurrency',
        'timeout-minutes',
        'GITHUB_STEP_SUMMARY',
        'security-control behavior unchanged',
    ]:
        if token not in changelog:
            errors.append(f'static workflow diagnostics changelog missing token {token}')

if errors:
    for error in errors:
        print(f'[static-check][FAIL] {error}', file=sys.stderr)
    sys.exit(1)
print('[static-check] workflow diagnostics coverage passed')
PY

note "checking restore release workflow diagnostics coverage"
python3 - <<'PY'
import pathlib
import sys

workflow_path = pathlib.Path('.github/workflows/restore-executor-release-gate.yml')
doc_path = pathlib.Path('docs/restore_release_gate_workflow_diagnostics.md')
changelog_path = pathlib.Path('docs/changelog_restore_release_summary.md')
errors = []

for path in [workflow_path, doc_path, changelog_path]:
    if not path.exists():
        errors.append(f'missing restore workflow diagnostics evidence file {path}')

if workflow_path.exists():
    workflow = workflow_path.read_text(encoding='utf-8')
    for token in [
        'Restore Executor Release Gate',
        'concurrency:',
        'cancel-in-progress: true',
        'timeout-minutes: 5',
        'Write restore release gate diagnostics summary',
        'GITHUB_STEP_SUMMARY',
        'restore-executor-release-evidence',
        'Run read-only wiring gate',
        'Build passive restore release summary evidence',
        'does not apply live restore actions or modify host, VM, hypervisor, firewall, service, IDS, network, or telemetry state',
    ]:
        if token not in workflow:
            errors.append(f'restore release workflow missing diagnostics token {token}')

if doc_path.exists():
    doc = doc_path.read_text(encoding='utf-8')
    for token in [
        'Restore Executor Release Gate',
        'GITHUB_STEP_SUMMARY',
        'restore-executor-release-evidence',
        'python3 host_vm_restore_executor_wiring_check.py',
        'Run read-only wiring gate',
        'Build passive restore release summary evidence',
        'diagnostics only',
        'rollback',
    ]:
        if token not in doc:
            errors.append(f'restore workflow diagnostics doc missing token {token}')

if changelog_path.exists():
    changelog = changelog_path.read_text(encoding='utf-8')
    for token in [
        'Restore gate workflow diagnostics',
        'docs/restore_release_gate_workflow_diagnostics.md',
        'GITHUB_STEP_SUMMARY',
        'restore-executor-release-evidence',
        'security',
        'rollback',
    ]:
        if token not in changelog:
            errors.append(f'restore workflow diagnostics changelog missing token {token}')

if errors:
    for error in errors:
        print(f'[static-check][FAIL] {error}', file=sys.stderr)
    sys.exit(1)
print('[static-check] restore release workflow diagnostics coverage passed')
PY

note "checking baseline hardening in high-risk systemd units"
for unit in \
    nn_ids_model_audit.service \
    nn_ids_audit_gate.service \
    host_vm_comm_guard.service \
    host_vm_policy_attest.service \
    host_vm_policy_verify.service \
    host_vm_policy_restore_execute.service; do
    require_file "$unit"
    grep -q '^NoNewPrivileges=true' "$unit" || fail "$unit missing NoNewPrivileges=true"
    grep -q '^PrivateTmp=true' "$unit" || fail "$unit missing PrivateTmp=true"
    grep -q '^ProtectSystem=' "$unit" || fail "$unit missing ProtectSystem"
done

note "running module-specific static tests"
while IFS= read -r -d '' test_script; do
    case "$(basename "$test_script")" in
        run_static_security_checks.sh) continue ;;
    esac
    bash "$test_script" || fail "module test failed: $test_script"
done < <(find tests -maxdepth 1 -type f -name 'test_*_static.sh' -print0 | sort -z)

if [[ "$failures" -ne 0 ]]; then
    fail "static validation completed with $failures failure(s)"
    exit 1
fi

note "all repo-wide static security checks passed"
