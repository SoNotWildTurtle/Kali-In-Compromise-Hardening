# Release Readiness Handoff Evidence

## Purpose

This guide defines the reviewer-facing evidence trail that should be preserved before promoting hardening, restore, or NN IDS changes into the default branch. It keeps release decisions grounded in passive validation artifacts instead of assumptions about live systems.

The handoff is intentionally additive. It does not add a new workflow, install packages, start services, contact external systems, alter branch protection, inspect live traffic, retrain models, apply restore actions, or change runtime policy enforcement.

## Minimum evidence set

Before merging a release-relevant PR, reviewers should be able to identify:

1. **Static Security Checks** result for repository-wide syntax, packaging, service-hardening, and static safety guardrails.
2. **Restore Executor Release Gate** result when restore executor, approval summary, firstboot, packaging, or service wiring changes are touched.
3. `restore-executor-release-evidence` artifact when restore release behavior is in scope.
4. NN IDS triage schemas, examples, bundle manifests, and validator output when IDS triage handoff behavior changes.
5. Changelog or follow-up notes describing compatibility, rollback, limitations, and next-step ownership.

## Reviewer triage order

1. Confirm the PR targets the intended base branch and has no stacked dependency waiting behind another open PR.
2. Check failed or queued required jobs before reviewing new functionality.
3. Inspect `GITHUB_STEP_SUMMARY` guidance for the first failing workflow step and local reproduction commands.
4. Inspect named artifacts only after their producer steps completed successfully.
5. Compare changelog and documentation notes against the code paths changed in the diff.
6. Re-run only failed jobs when the failure is transient; fix root causes when assertions, packaging, or workflow contracts fail.

## Local reproduction anchors

Use the narrowest relevant command before broad validation:

```bash
bash tests/run_static_security_checks.sh
```

For restore release evidence, reproduce the read-only wiring path first:

```bash
python3 host_vm_restore_executor_wiring_check.py \
  --root . \
  --strict \
  --output /tmp/restore-executor-wiring.json \
  --report /tmp/restore-executor-wiring.report
```

Then run the module-specific static test matching the touched helper, schema, example, or workflow document.

## Compatibility and rollback

This guide is documentation and static guardrail scope only. Reverting this guide, its changelog entry, and related static coverage does not require live-system rollback.

## Follow-up work

- Promote this handoff guide into a generated aggregate release-readiness summary only if reviewers start needing a single cross-workflow artifact.
- Keep workflow additions small and tied to recurring reviewer handoff gaps.
- Add dependency-free schema field checks only when artifact consumers depend on those fields.
