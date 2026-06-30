# Changelog: Firstboot Handoff Release Receipt

## Added

- Added `host_vm_policy_firstboot_release_receipt.py`, a passive standard-library receipt generator for firstboot handoff gate evidence.
- Added `tests/test_host_vm_policy_firstboot_release_receipt_static.sh` with synthetic passing and blocked gate evidence coverage.
- Extended `.github/workflows/firstboot-handoff-release-gate.yml` so hosted validation now creates and verifies `firstboot_release_receipt.json` and `firstboot_release_receipt.report` before uploading aggregate handoff evidence.
- Extended workflow static checks to keep the receipt step wired and passive.

## Safety and compatibility

- The receipt reads only aggregate gate evidence and does not mutate host or VM state.
- Existing firstboot, packaging, restore executor, IDS, validator, dry-run wrapper, and operator workflows remain unchanged.
- The hosted workflow remains passive and uses synthetic aggregate evidence.

## Validation

Focused validation for this increment:

```bash
bash tests/test_host_vm_policy_firstboot_release_receipt_static.sh
bash tests/test_firstboot_handoff_release_gate_workflow_static.sh
bash tests/test_host_vm_policy_firstboot_handoff_gate_static.sh
bash tests/run_static_security_checks.sh
```

Hosted workflow validation is required before merge.

## Rollback

Revert `host_vm_policy_firstboot_release_receipt.py`, `tests/test_host_vm_policy_firstboot_release_receipt_static.sh`, this changelog file, and the receipt-related edits to `.github/workflows/firstboot-handoff-release-gate.yml`, `tests/test_firstboot_handoff_release_gate_workflow_static.sh`, and `docs/host_vm_policy_firstboot_handoff_gate.md`. No live system state requires rollback.

## Follow-up

- Feed the firstboot release receipt into a broader release-readiness receipt alongside restore executor and IDS audit evidence.
- Add expected-blocked receipt fixtures once the aggregate release receipt can distinguish intentional blocked cases from workflow failures.
