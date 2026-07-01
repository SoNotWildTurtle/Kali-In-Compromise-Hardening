# Changelog: Aggregate Release Posture Evidence Manifest

## Added

- Added an `evidence_manifest` object to `host_vm_policy_release_posture_summary.py` output so release reviewers can identify schema, local validation commands, hosted gate expectations, publication safety, and human-review requirements from the artifact itself.
- Added compact report fields for `schema_path`, `safe_to_publish`, `contains_raw_telemetry`, `contains_secrets`, and `human_review_required`.
- Extended the aggregate release posture JSON Schema to require the manifest and preserve safe publication invariants.
- Expanded static and schema tests to cover ready and blocked artifacts with manifest fields.
- Updated posture summary documentation with evidence manifest semantics, validation, compatibility, rollback notes, and follow-up work.

## Safety and compatibility

- This increment is passive artifact metadata and validation only.
- It does not execute firstboot, execute restore actions, mutate host or VM state, install packages, reload services, change firewall rules, read raw telemetry, load IDS datasets or models, contact external systems, or add persistence.
- Existing firstboot, restore, packaging, services, smoke checks, IDS behavior, and user workflows remain unchanged.
- The JSON artifact is additively extended; existing readiness, component, blocking issue, reviewer handoff, rollback, and report fields are preserved.
- Rollback is a normal revert of the script, schema, tests, documentation update, and this changelog.

## Validation

Focused validation for this increment:

```bash
python3 -m py_compile host_vm_policy_release_posture_summary.py
bash tests/test_host_vm_policy_release_posture_summary_static.sh
bash tests/test_host_vm_policy_release_posture_summary_schema_static.sh
bash tests/run_static_security_checks.sh
```

Hosted validation required before merge:

```text
Static Security Checks
Restore Executor Release Gate
```

## Follow-up

- Add IDS aggregate release evidence once IDS artifacts expose matching passive ready/blocked semantics.
- Wire firstboot, restore, and IDS posture evidence into a hosted aggregate release gate.
- Add hosted JSON Schema validation once the repository adopts a reusable validator.
