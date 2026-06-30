# Changelog: Firstboot Release Receipt Blocked Examples

## Added

- Added `docs/firstboot_release_receipt_blocked_examples.md` to explain expected blocked release receipt behavior for normal blocked and malformed aggregate gate evidence.
- Extended `tests/test_host_vm_policy_firstboot_release_receipt_static.sh` with a malformed synthetic gate fixture that verifies non-strict blocked artifact generation and explicit blocker reporting.
- Linked the blocked examples from `docs/host_vm_policy_firstboot_handoff_gate.md`.

## Safety and compatibility

- The increment is documentation and static-test only.
- All fixtures are synthetic aggregate evidence.
- No host or VM state is read or changed.
- Existing validator, firstboot, restore executor, IDS, packaging, service, and workflow behavior remains unchanged.

## Validation

Focused validation for this increment:

```bash
bash tests/test_host_vm_policy_firstboot_release_receipt_static.sh
bash tests/run_static_security_checks.sh
```

Hosted workflow validation is required before merge.

## Rollback

Revert this changelog file, `docs/firstboot_release_receipt_blocked_examples.md`, the link added to `docs/host_vm_policy_firstboot_handoff_gate.md`, and the malformed-gate fixture additions in `tests/test_host_vm_policy_firstboot_release_receipt_static.sh`. No live system state requires rollback.

## Follow-up

- Publish expected-negative blocked receipt artifacts in CI once the aggregate release gate can mark them as fixtures instead of failures.
- Feed receipt blocker categories into a broader release readiness summary with restore executor and IDS audit evidence.
