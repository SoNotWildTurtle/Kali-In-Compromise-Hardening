# Changelog: Host/VM Policy Firstboot Dry-Run Wrapper

## Added

- Added `host_vm_policy_firstboot_dry_run.py`, a passive standard-library CLI that composes the existing Host/VM policy validator and writes aggregate firstboot review evidence.
- Added machine-readable evidence, manifest, and handoff JSON outputs with optional Markdown operator evidence.
- Added output-directory guardrails that require runtime evidence paths to stay under `/var/log` or `/var/lib` unless an explicit test-only override is used.
- Added regression coverage for valid profiles, invalid-profile evidence, output path rejection, CLI error handling, and privacy-safe handoff content.
- Added wrapper documentation with usage, exit codes, threat-model rationale, rollback notes, and follow-up work.

## Safety and compatibility

- No live host, VM, firewall, service, network interface, package, credential, account, IDS runtime, model, dataset, recovery, approval, scheduled-task, or remote-access state is changed.
- Existing validator CLI behavior remains unchanged.
- The wrapper emits aggregate evidence only and records rollback as deletion of generated dry-run artifacts.

## Validation

Focused local validation for this increment:

```bash
python3 -m pytest tests/test_host_vm_policy_firstboot_dry_run.py
python3 -m py_compile host_vm_policy_firstboot_dry_run.py host_vm_policy_validator.py
```

Hosted workflow validation is required before merge.

## Rollback

Revert the wrapper, tests, documentation, and changelog file. No live system state requires rollback.

## Follow-up

- Feed the generated handoff JSON into release-gate aggregation.
- Add firstboot packaging integration only after release-gate consumption is covered.
- Add checked-in example profiles that demonstrate default review, strict release promotion, and recovery handoff modes.
