# Changelog: Restore Release Readiness Summary

## Added

- Added `host_vm_policy_restore_release_summary.py`, a passive aggregate-only summary CLI for manual restore executor evidence.
- Added behavioral/static coverage in `tests/test_host_vm_policy_restore_release_summary_static.sh` for ready, expected-blocked, and malformed live-state evidence.
- Documented reviewer usage, threat-model rationale, rollback notes, validation commands, known limits, and follow-up work in `docs/host_vm_policy_restore_release_summary.md`.

## Hosted evidence wiring

- Wired the restore release summary into the `Restore Executor Release Gate` workflow.
- Added synthetic, non-mutating hosted fixtures for ready dry-run evidence and expected-blocked approval evidence.
- Uploaded `restore-executor-release-evidence` artifacts containing wiring, ready, blocked, and summary JSON/report files.
- Extended static coverage so future edits must keep hosted summary artifacts discoverable from the release workflow.

## JSON Schema contract

- Added `docs/schemas/host_vm_policy_restore_release_summary.schema.json` as the machine-readable contract for passive restore summary artifacts.
- Pinned non-mutating safety fields including `changes_live_state=false`, `reads_raw_telemetry=false`, `aggregate_evidence_only=true`, and `requires_manual_invocation=true`.
- Linked `restore_summary_ready` to zero blocking issues and `restore_summary_blocked` to at least one blocker so downstream release gates can detect incompatible evidence.
- Extended static coverage and reviewer documentation so schema drift is visible before artifact consumers depend on the contract.

## Safety and compatibility

- This increment only reads synthetic or reviewer-provided restore executor JSON.
- It does not install packages, start services, change firewall rules, alter host or VM state, collect credentials, read raw telemetry, access IDS datasets/models, or contact external systems.
- Existing firstboot gate, release receipt, restore executor, IDS, packaging, services, and operator workflows remain unchanged.
- The summary, schema, and hosted evidence wiring can be reverted independently because they only add reviewer evidence, documentation, workflow artifact publication, and test coverage.

## Validation

Focused validation for this increment:

```bash
bash tests/test_host_vm_policy_restore_release_summary_static.sh
bash tests/run_static_security_checks.sh
```

Hosted validation required before merge:

```text
Restore Executor Release Gate
Static Security Checks
```

## Rollback

Revert this changelog, `host_vm_policy_restore_release_summary.py`, `tests/test_host_vm_policy_restore_release_summary_static.sh`, `docs/host_vm_policy_restore_release_summary.md`, `docs/schemas/host_vm_policy_restore_release_summary.schema.json`, and the restore release workflow wiring. No live system state requires rollback.

## Follow-up

- Feed restore summary output into aggregate firstboot/restore/IDS posture evidence.
- Add reviewer-facing release notes whenever expected-blocked restore semantics change.
- Add hosted schema validation after the repository standardizes on a JSON Schema validator dependency.
