# Restore Release Gate Workflow Diagnostics

## Purpose

The `Restore Executor Release Gate` workflow emits reviewer-facing diagnostics through `GITHUB_STEP_SUMMARY` and uploads the `restore-executor-release-evidence` artifact. The summary gives maintainers a stable scope statement, local reproduction guidance, first-failure triage targets, and the exact artifact name to inspect before changing restore release behavior.

This is diagnostics only. It uses read-only wiring checks and synthetic restore approval fixtures. It does not apply live restore actions, install packages, start or stop services, alter host or VM state, modify firewall rules, inspect raw IDS traffic, collect credentials, contact external systems, or change runtime policy enforcement.

## Local reproduction

Run the read-only wiring gate first:

```bash
python3 host_vm_restore_executor_wiring_check.py \
  --root . \
  --strict \
  --output /tmp/restore-executor-wiring.json \
  --report /tmp/restore-executor-wiring.report
```

Then reproduce the passive ready and blocked restore approval fixtures from `.github/workflows/restore-executor-release-gate.yml`. The hosted workflow writes the generated JSON and report files into the `restore-executor-release-evidence` artifact so reviewers can compare the local and hosted evidence paths.

## Failure triage order

1. Inspect **Run read-only wiring gate** when package, firstboot, service, smoke-check, or restore executor wiring evidence is missing.
2. Inspect **Build passive restore release summary evidence** when ready, blocked, schema, summary, or report generation fails.
3. Inspect **Upload restore release evidence** only after the previous steps have produced the expected files.

## Workflow behavior

- Uses `concurrency` with `cancel-in-progress: true` so stale branch evidence is replaced by the newest same-ref run.
- Uses `timeout-minutes: 5` to keep release-gate diagnostics bounded.
- Writes `GITHUB_STEP_SUMMARY` guidance even when a validation step fails.
- Uploads `restore-executor-release-evidence` with wiring, ready, blocked, and summary JSON/report files.
- Keeps workflow scope passive and release-review oriented rather than live restore execution.

## Compatibility and rollback

This is additive and backwards compatible. Rollback is a normal revert of `.github/workflows/restore-executor-release-gate.yml`, this document, `docs/changelog_restore_release_summary.md`, and the related static coverage in `tests/run_static_security_checks.sh`. No host, VM, IDS, firewall, restore, package, service, telemetry, or hypervisor state requires rollback.

## Follow-up work

- Promote restore release gate evidence into aggregate release-readiness handoff only if reviewers need cross-workflow posture summaries.
- Add dependency-free schema field checks to the workflow only if artifact consumers start depending on more summary fields.
- Keep future workflow changes small, justified by recurring failures or handoff gaps, and validated by static coverage.
