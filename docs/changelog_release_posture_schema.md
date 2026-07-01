# Changelog: Aggregate Release Posture Schema Contract

## Added

- Added `docs/schemas/host_vm_policy_release_posture_summary.schema.json` to document the machine-readable contract for aggregate posture artifacts.
- Added `tests/test_host_vm_policy_release_posture_summary_schema_static.sh`, a dependency-free schema fixture test that validates ready and blocked synthetic posture outputs against the critical contract fields.
- Updated `docs/host_vm_policy_release_posture_summary.md` with schema location, safety invariants, validation commands, rollback notes, limitations, and follow-up work.

## Safety and compatibility

- This increment is documentation and static validation only.
- It does not execute firstboot, execute restore actions, mutate host or VM state, install packages, reload services, change firewall rules, read raw telemetry, load IDS datasets or models, contact external systems, or add persistence.
- Existing firstboot, restore, packaging, services, smoke checks, IDS behavior, and user workflows remain unchanged.
- Rollback is a normal revert of the schema, schema static test, documentation update, and this changelog.

## Validation

Focused validation for this increment:

```bash
bash tests/test_host_vm_policy_release_posture_summary_schema_static.sh
bash tests/run_static_security_checks.sh
```

Hosted validation required before merge:

```text
Static Security Checks
```

## Follow-up

- Add IDS aggregate release evidence once IDS artifacts expose matching passive ready/blocked semantics.
- Add hosted schema validation once the repository adopts a JSON Schema dependency or reusable validator.
- Wire the posture summary into hosted release gates after firstboot, restore, and IDS artifacts are available in one workflow context.
