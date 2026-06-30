# Changelog: Host/VM Policy Firstboot Dry-Run Plan

## Added

- Added `docs/host_vm_policy_firstboot_dry_run_plan.md` as a documentation-only integration plan for the next passive firstboot handoff step.
- Captured the expected evidence filenames, handoff fields, output-location policy, rollback notes, and future test plan.
- Added static documentation coverage in `tests/test_host_vm_policy_firstboot_dry_run_plan.py`.

## Safety and compatibility

- No live host, VM, service, firewall, network interface, package, credential, IDS, model, dataset, recovery, approval, scheduled-task, or account state is changed.
- Existing validator CLI behavior remains unchanged.
- Rollback is limited to reverting this planning document, its README reference, changelog, and static tests.

## Follow-up

- Add the standard-library dry-run wrapper in a focused implementation PR after this planning contract is merged.
- Add release-gate aggregation once wrapper output exists and has green CI evidence.
