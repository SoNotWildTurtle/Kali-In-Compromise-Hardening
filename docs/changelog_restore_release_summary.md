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

## Safety and compatibility

- This increment only reads synthetic or reviewer-provided restore executor JSON.
- It does not install packages, start services, change firewall rules, alter host or VM state, collect credentials, read raw telemetry, access IDS datasets/models, or contact external systems.
- Existing firstboot gate, release receipt, restore executor, IDS, packaging, services, and operator workflows remain unchanged.
- The summary and hosted evidence wiring can be reverted independently because they only add reviewer evidence, documentation, workflow artifact publication, and test coverage.

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

Revert this changelog, `host_vm_policy_restore_release_summary.py`, `tests/test_host_vm_policy_restore_release_summary_static.sh`, `docs/host_vm_policy_restore_release_summary.md`, and the restore release workflow wiring. No live system state requires rollback.

## Follow-up

- Feed restore summary output into aggregate firstboot/restore/IDS posture evidence.
- Add reviewer-facing release notes whenever expected-blocked restore semantics change.
- Consider adding a JSON Schema for restore summary artifacts once downstream consumers rely on the hosted evidence contract.
