# Changelog Fragment: Host/VM Policy Configuration Schema

## Added

- Added `docs/host_vm_policy_configuration_schema.json`, a passive JSON Schema contract for reviewing host/VM policy configuration before future firstboot or release-gate promotion.
- Added `docs/host_vm_policy_configuration_schema.md` with configuration fields, an example policy profile, review guidance, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.
- Added `tests/test_host_vm_policy_configuration_schema.py` to statically verify the schema contract, documentation coverage, safety defaults, privacy boundaries, and changelog traceability.

## Security

- The schema requires authorized defensive use, explicit operator acknowledgement, aggregate-only evidence, and `remote_host_mutation_allowed: false` for passive policy review.
- Artifact paths are constrained to aggregate evidence locations under `/var/log` or `/var/lib`.
- Privacy boundaries explicitly exclude raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, datasets, private keys, and tokens.

## Compatibility

- Documentation/static-validation only; no runtime behavior, package wiring, firstboot behavior, host state, VM state, firewall rules, network interfaces, services, approvals, restores, IDS models, datasets, accounts, or credentials are changed.

## Rollback

- Delete `docs/host_vm_policy_configuration_schema.json`, `docs/host_vm_policy_configuration_schema.md`, `docs/changelog_host_vm_policy_configuration_schema.md`, and `tests/test_host_vm_policy_configuration_schema.py`.
- No deployed host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, account, or package state requires rollback.
