# Changelog Fragment: Host/VM Policy Example Profiles

## Added

- Added `examples/host_vm_policy_default_review.json` as the baseline firstboot review profile used by validator documentation.
- Added `examples/host_vm_policy_strict_review.json` as a tighter freshness profile for reviews that need more recent aggregate evidence.
- Added `examples/host_vm_policy_recovery_handoff.json` as an operator handoff profile for recovery review windows.
- Added `tests/test_host_vm_policy_example_profiles.py` to validate every checked-in example profile with `host_vm_policy_validator.py`.

## Security

- All profiles keep `remote_host_mutation_allowed: false` and require explicit defensive-use acknowledgement.
- All profiles require aggregate-only privacy boundaries and exclude raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, datasets, private keys, and tokens.
- All profiles preserve file-only rollback and require no live host or VM state rollback.

## Compatibility

- Examples are passive JSON files consumed by the standard-library validator.
- Existing CLI behavior, firstboot behavior, services, package state, host state, VM state, IDS models, datasets, credentials, approval state, and recovery state remain unchanged.

## Rollback

- Delete the three `examples/host_vm_policy_*.json` files, `tests/test_host_vm_policy_example_profiles.py`, this changelog fragment, and the documentation references added for the examples.
- No live host, VM, service, network, IDS, credential, account, package, approval, restore, or recovery state requires rollback.
