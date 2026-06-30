# Changelog: Firstboot Blocked Fixture Artifacts

## Added

- Added an expected-blocked synthetic fixture path to `.github/workflows/firstboot-handoff-release-gate.yml`.
- The workflow now creates aggregate-only invalid-profile evidence, evaluates it without `--strict`, verifies `release_blocked` and `release_receipt_blocked`, and uploads the blocked gate and receipt artifacts under `firstboot-handoff-gate-blocked-fixture`.
- Extended `tests/test_firstboot_handoff_release_gate_workflow_static.sh` so the passive workflow wiring must retain the expected-negative fixture, blocked receipt checks, and artifact upload.
- Updated `docs/host_vm_policy_firstboot_handoff_gate.md` with reviewer guidance for comparing release-ready artifacts with expected-blocked artifacts.

## Safety and compatibility

- The increment is CI evidence wiring, documentation, and static-test coverage only.
- All fixture inputs are synthetic aggregate evidence.
- The primary release gate remains strict and fail-closed for the release-ready bundle.
- The expected-blocked fixture is generated without `--strict` so reviewers receive negative evidence artifacts without treating the negative fixture itself as a workflow failure.
- No host or VM state is read or changed.
- Existing validator, firstboot, restore executor, IDS, packaging, service, and operator behavior remains unchanged.

## Validation

Focused validation for this increment:

```bash
bash tests/test_firstboot_handoff_release_gate_workflow_static.sh
bash tests/run_static_security_checks.sh
```

Hosted workflow validation is required before merge.

## Rollback

Revert this changelog file, the workflow blocked-fixture step and upload block, the static workflow-test assertions, and the hosted-workflow documentation paragraph in `docs/host_vm_policy_firstboot_handoff_gate.md`. No live system state requires rollback.

## Follow-up

- Feed ready and expected-blocked receipt artifact metadata into a broader release-readiness summary alongside restore executor and IDS aggregate evidence.
- Add a compact reviewer note to future release notes when the expected-blocked fixture changes, so branch-stack reviewers can distinguish expected-negative evidence from real CI failures.
