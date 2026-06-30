# Changelog: Firstboot Release Readiness Summary

## Added

- Added `host_vm_policy_firstboot_release_summary.py`, a passive aggregate-only summary CLI for firstboot release receipt evidence.
- Added behavioral/static coverage in `tests/test_host_vm_policy_firstboot_release_summary_static.sh` for ready, optional expected-blocked, and malformed receipt cases.
- Documented reviewer usage, threat-model rationale, rollback notes, validation commands, and follow-up work in `docs/host_vm_policy_firstboot_release_summary.md`.
- Wired the release summary into the hosted `Firstboot Handoff Release Gate` workflow so CI uploads `firstboot_release_summary.json` and `firstboot_release_summary.report` with the ready evidence bundle.
- Extended workflow static coverage to require summary generation, expected-blocked comparison, artifact upload paths, and strict passive-only command boundaries.

## Safety and compatibility

- This increment only reads synthetic aggregate receipt JSON created by the passive release receipt workflow or by local reviewer fixtures.
- It does not install packages, start services, change firewall rules, alter host or VM state, collect credentials, read raw telemetry, access IDS datasets/models, or contact external systems.
- Existing validator, dry-run wrapper, release gate, release receipt, restore executor, IDS, packaging, service, and operator behavior remain unchanged.
- The summary can be reverted independently because it only adds reviewer evidence, documentation, workflow wiring, and test coverage.

## Validation

Focused validation for this increment:

```bash
bash tests/test_host_vm_policy_firstboot_release_summary_static.sh
bash tests/test_firstboot_handoff_release_gate_workflow_static.sh
bash tests/run_static_security_checks.sh
```

Hosted static security validation is required before merge.

## Rollback

Revert this changelog, `host_vm_policy_firstboot_release_summary.py`, `tests/test_host_vm_policy_firstboot_release_summary_static.sh`, `tests/test_firstboot_handoff_release_gate_workflow_static.sh`, `.github/workflows/firstboot-handoff-release-gate.yml`, and `docs/host_vm_policy_firstboot_release_summary.md`. No live system state requires rollback.

## Follow-up

- Extend the summary with restore executor and IDS aggregate release evidence after those components expose compatible ready and expected-blocked receipts.
- Add reviewer release notes whenever expected-blocked summary semantics change.
- Keep live firstboot packaging behind repeated green hosted summary evidence and explicit human review.
