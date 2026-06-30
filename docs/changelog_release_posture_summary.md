# Changelog: Aggregate Release Posture Summary

## Added

- Added `host_vm_policy_release_posture_summary.py`, a passive aggregate CLI that combines firstboot and restore release summaries into one reviewer-facing posture artifact.
- Added `tests/test_host_vm_policy_release_posture_summary_static.sh` with ready and blocked synthetic examples, strict-mode behavior, compact report checks, and passive safety assertions.
- Documented usage, input contracts, output decisions, threat-model rationale, validation, rollback notes, limitations, and follow-up work in `docs/host_vm_policy_release_posture_summary.md`.

## Safety and compatibility

- This increment reads only aggregate firstboot and restore summary JSON.
- It does not execute firstboot, execute restore actions, mutate host or VM state, install packages, reload services, modify firewall rules, read raw telemetry, load IDS datasets/models, contact external systems, or add persistence.
- Existing firstboot, restore, packaging, services, smoke checks, IDS behavior, and user workflows remain unchanged.
- Rollback is a normal revert of the posture summary CLI, static test, documentation, and changelog.

## Validation

Focused validation for this increment:

```bash
bash tests/test_host_vm_policy_release_posture_summary_static.sh
bash tests/run_static_security_checks.sh
```

Hosted validation required before merge:

```text
Static Security Checks
```

## Follow-up

- Add IDS aggregate release evidence once IDS artifacts expose matching passive ready/blocked semantics.
- Publish a JSON Schema contract for aggregate posture output after the field set stabilizes.
- Wire the posture summary into hosted release gates after firstboot and restore artifacts are available in a shared workflow context.
