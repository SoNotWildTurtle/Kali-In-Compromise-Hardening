# Changelog: Firstboot Handoff Gate

## Added

- Added `host_vm_policy_firstboot_handoff_gate.py`, a passive standard-library CLI that validates aggregate firstboot handoff JSON before release promotion.
- Added strict checks for producer identity, schema version, profile validation status, passive safety flags, privacy boundaries, rollback scope, required artifact declarations, and optional local artifact existence.
- Added compact JSON/report outputs that can feed future release-readiness receipts.
- Added a static regression test that creates synthetic aggregate evidence, confirms a release-ready handoff passes, and confirms unsafe handoff flags are blocked.
- Added operator documentation with usage, exit behavior, rollback notes, and follow-up work.

## Safety and compatibility

- No live system, service, account, package, IDS runtime, model, dataset, approval, recovery, or scheduled-task state is changed.
- Existing validator, dry-run wrapper, restore executor, firstboot, packaging, systemd, and IDS workflows remain unchanged.
- The new gate reads aggregate handoff evidence only and defaults to fail-closed strict behavior for release promotion.

## Validation

Focused validation for this increment:

```bash
python3 -m py_compile host_vm_policy_firstboot_handoff_gate.py
bash tests/test_host_vm_policy_firstboot_handoff_gate_static.sh
bash tests/run_static_security_checks.sh
```

Hosted workflow validation is required before merge.

## Rollback

Revert the handoff gate, static test, documentation, and changelog file. No live system state requires rollback.

## Follow-up

- Add a dedicated hosted workflow that runs the handoff gate against a generated dry-run bundle.
- Add packaging/firstboot wiring only after hosted release-gate coverage is green.
- Feed the gate decision into a broader release-readiness receipt.
