# Manual Restore Executor Release Gate

`restore-executor-release-gate.yml` runs the read-only `host_vm_restore_executor_wiring_check.py` gate in GitHub Actions whenever the manual restore executor, ISO packaging, firstboot flow, smoke checks, static tests, or related documentation changes.

## Purpose

The manual restore executor is intentionally high-consequence. Even though it defaults to dry-run and requires explicit `--execute`, it must not be released unless repository wiring proves that:

- the executor and one-shot service are present;
- `build_custom_iso.sh` packages the executor and service;
- `vm_smoke_check.sh` validates executor artifacts;
- repo static checks include the executor tests;
- documentation describes dry-run, approval validation, and the no-timer rule;
- no recurring `host_vm_policy_restore_execute.timer` exists or is referenced.

## Safety model

The workflow only checks repository text. It does not run nftables, systemctl, model retraining, rollback, or host/VM mutation commands. The output JSON and compact report are uploaded as artifacts so a reviewer can see exactly which wiring requirements passed or failed.

## Expected current behavior

Until `build_custom_iso.sh`, `vm_smoke_check.sh`, and `tests/run_static_security_checks.sh` are updated to include the restore executor, this workflow is expected to fail with `wiring_review_required`. That failure is useful: it prevents the manual restore path from silently drifting into a partially packaged state.

## Operational rationale

This maps the recovery workflow to reviewable, automated checks before any restoration path can be considered release-ready. It supports configuration-management, auditability, and recovery-assurance goals without weakening the default no-live-restore posture.
