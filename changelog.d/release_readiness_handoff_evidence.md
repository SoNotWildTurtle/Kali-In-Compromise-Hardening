# Release readiness handoff evidence

## Added

- Added `docs/release_readiness_handoff_evidence.md` to document the minimum passive evidence set reviewers should inspect before merging release-relevant hardening, restore, or NN IDS changes.
- Captured a consistent triage order for base-branch correctness, stacked PR dependencies, required checks, `GITHUB_STEP_SUMMARY` guidance, named artifacts, changelog notes, rollback notes, and local reproduction commands.
- Added static coverage so the handoff guide continues to reference `Static Security Checks`, `Restore Executor Release Gate`, `restore-executor-release-evidence`, NN IDS triage evidence, and rollback guidance.

## Safety and compatibility

- Documentation and static guardrail scope only.
- Does not change runtime policy enforcement, restore execution, IDS inference, firstboot behavior, packaging, services, firewall rules, workflow names, required checks, branch protection, or artifact names.
- Backwards compatible and reversible through a normal revert of this changelog, the handoff guide, and related static coverage.

## Validation

- `bash tests/run_static_security_checks.sh`

## Follow-up

- Promote the guide into an aggregate generated release-readiness artifact only if reviewers need one cross-workflow handoff surface.
- Keep future workflow additions small, evidence-driven, and tied to recurring validation or reviewer handoff gaps.
