# Static Workflow Diagnostics

## Added

- Added a `GITHUB_STEP_SUMMARY` diagnostics step to the `Static Security Checks` workflow so reviewers can quickly find the reproduction command, failing step, workflow source, and safety boundary.
- Added `concurrency` with `cancel-in-progress: true` so obsolete static-check runs do not obscure the newest branch evidence.
- Added `timeout-minutes: 10` to keep static validation bounded.
- Added documentation and repo-wide static coverage so the diagnostics behavior is preserved as workflows evolve.

## Security

- Runtime and security-control behavior unchanged.
- The workflow summary is diagnostics only and does not inspect live IDS, host, VM, hypervisor, packet, payload, firewall, restore, retraining, service, network, or telemetry state.
- No host hardening, VM hardening, IDS model, firstboot, restore executor, systemd service, timer, firewall, package, or telemetry behavior changed.

## Validation

- Workflow diagnostics coverage is enforced by `bash tests/run_static_security_checks.sh`.
- Hosted validation remains the `Static Security Checks` workflow and any existing release gates triggered by changed paths.

## Rollback

Rollback is a normal revert of `.github/workflows/static-security-checks.yml`, `tests/run_static_security_checks.sh`, `docs/static_workflow_diagnostics.md`, and this changelog entry. No runtime state requires rollback.
