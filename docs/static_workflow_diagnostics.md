# Static Workflow Diagnostics

## Purpose

The `Static Security Checks` workflow now emits a concise GitHub Actions step summary after every run. The summary gives reviewers a stable reproduction command, the first step to inspect when validation fails, and the workflow source file to review before changing CI behavior.

This is diagnostics only. It does not inspect live IDS, host, VM, hypervisor, packet, payload, firewall, restore, retraining, service, network, or telemetry state. It does not change host hardening, VM hardening, IDS model behavior, firstboot wiring, restore execution, systemd services, timers, or runtime policy enforcement.

## Local reproduction

```bash
bash tests/run_static_security_checks.sh
```

When hosted CI fails, inspect the `Run defensive static checks` step first, then use the local command above to reproduce the same repo-wide static validation path.

## Workflow behavior

- Uses a short `timeout-minutes` budget so static validation cannot hang indefinitely.
- Uses `concurrency` with `cancel-in-progress: true` so outdated static runs do not obscure the newest branch evidence.
- Writes reviewer guidance to `GITHUB_STEP_SUMMARY` even when validation fails.
- Keeps the original workflow name and check purpose intact for branch-protection compatibility.

## Compatibility and rollback

This is additive and backwards compatible. Rollback is a normal revert of `.github/workflows/static-security-checks.yml`, this document, `tests/run_static_security_checks.sh`, and `changelog.d/static_workflow_diagnostics.md`. No runtime host, VM, IDS, firewall, restore, telemetry, package, or systemd state requires rollback.

## Follow-up work

- Add similarly scoped summaries to release-gate workflows when those jobs gain more artifact-producing steps.
- Consider uploading static-check text artifacts only if future failures show the step summary is insufficient.
- Keep workflow evolution small and tied to recurring validation or handoff gaps.
