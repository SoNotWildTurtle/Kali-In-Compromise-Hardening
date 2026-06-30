# Changelog Fragment: Host/VM Policy Validator CLI

## Added

- Added `host_vm_policy_validator.py`, an offline standard-library CLI that validates passive Host/VM policy profiles and emits JSON or Markdown evidence.
- Added `docs/host_vm_policy_validator_cli.md` with safety model, usage examples, validation coverage, compatibility, rollback, and follow-up work.
- Added `tests/test_host_vm_policy_validator_cli.py` to cover valid profiles, unsafe mutation/privacy failures, Markdown output, file output, and documentation traceability.

## Security

- The validator is passive and file-based; it does not mutate host or VM state.
- Validation rejects remote host mutation, unsafe artifact paths, insufficient privacy exclusions, non-aggregate privacy settings, and live-state rollback requirements.
- Output evidence explicitly records `mutates_host_or_vm_state: false`, `reads_raw_telemetry: false`, and `emits_aggregate_review_evidence: true`.

## Compatibility

- Uses only the Python standard library.
- No service, timer, firstboot hook, firewall rule, network interface, package, approval state, restore state, IDS model, dataset, credential, account, host state, or VM state is changed.

## Rollback

- Delete `host_vm_policy_validator.py`, `docs/host_vm_policy_validator_cli.md`, `docs/changelog_host_vm_policy_validator_cli.md`, and `tests/test_host_vm_policy_validator_cli.py`.
- No deployed service, firstboot, host, VM, firewall, network, approval, restore, IDS, model, dataset, credential, account, or package state requires rollback.
