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
