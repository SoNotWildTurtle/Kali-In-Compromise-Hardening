# Changelog: Firstboot Handoff Release Gate Workflow

## Added

- Added `.github/workflows/firstboot-handoff-release-gate.yml`, a passive hosted workflow that exercises the firstboot handoff release gate on pull requests and pushes touching the handoff gate, dry-run wrapper, workflow, or related static tests.
- Added `tests/test_firstboot_handoff_release_gate_workflow_static.sh` to keep workflow wiring reviewable under repo-wide static checks.
- The workflow builds synthetic aggregate handoff evidence, runs `host_vm_policy_firstboot_handoff_gate.py --strict`, verifies the `release_ready` decision, and uploads the aggregate handoff gate evidence artifact.

## Safety and compatibility

- The workflow does not mutate host or VM state, install packages, start services, change firewall rules, perform network fetches, collect credentials, or read raw telemetry.
- Existing packaging, firstboot, restore executor, IDS, validator, and operator workflows remain unchanged.
- The workflow uses only repository scripts, shell built-ins, Python already present on the hosted runner, and GitHub artifact upload.

## Validation

Focused validation for this increment:

```bash
bash tests/test_firstboot_handoff_release_gate_workflow_static.sh
bash tests/test_host_vm_policy_firstboot_handoff_gate_static.sh
bash tests/run_static_security_checks.sh
```

Hosted workflow validation is required before merge.

## Rollback

Revert `.github/workflows/firstboot-handoff-release-gate.yml`, `tests/test_firstboot_handoff_release_gate_workflow_static.sh`, and this changelog file. No live system state requires rollback.

## Follow-up

- Feed the uploaded gate evidence into a broader aggregate release-readiness receipt.
- Add packaging/firstboot wiring only after repeated hosted handoff-gate runs stay green.
- Add a matrix case for intentionally blocked handoff evidence once the release receipt can distinguish expected failure artifacts from release failures.
