# Host/VM Restore Release Readiness Summary

`host_vm_policy_restore_release_summary.py` creates a compact, machine-readable handoff from passive restore executor evidence. It is intended for reviewers who need to confirm that the manual restore executor is ready for release review without enabling any live restore path.

The summary compares:

- a ready dry-run result with `decision=restore_ready_dry_run`, and
- an optional expected-blocked fixture with `decision=restore_blocked`.

The tool is aggregate-only. It does not read raw telemetry, packet captures, hostnames, usernames, credentials, model binaries, datasets, private keys, tokens, logs, live service state, firewall state, package state, or hypervisor state. It only validates JSON fields already emitted by the manual restore executor or by synthetic reviewer fixtures.

## Threat-model rationale

Restore execution is deliberately manual, approval-gated, and dry-run by default. The release summary keeps that boundary intact by checking only review evidence. It helps reviewers verify that the ready path remains non-mutating while an expected-negative fixture still fails closed.

Safe-by-default markers:

- `changes_live_state=false`
- `reads_raw_telemetry=false`
- `aggregate_evidence_only=true`
- `requires_manual_invocation=true`
- `--strict` exits non-zero unless the summary is ready

## Usage

Build a summary from a ready dry-run result:

```bash
python3 host_vm_policy_restore_release_summary.py \
  /tmp/restore/restore_ready.json \
  --output /tmp/restore/restore_release_summary.json \
  --report /tmp/restore/restore_release_summary.report \
  --strict
```

Build a summary that also compares expected-blocked evidence:

```bash
python3 host_vm_policy_restore_release_summary.py \
  /tmp/restore/restore_ready.json \
  --expected-blocked-result /tmp/restore/restore_blocked.json \
  --output /tmp/restore/restore_release_summary.json \
  --report /tmp/restore/restore_release_summary.report \
  --strict
```

A ready summary reports:

```text
decision=restore_summary_ready
summary_ready=true
ready_restore_decision=restore_ready_dry_run
expected_blocked_decision=restore_blocked
blocking_issue_count=0
```

A blocked summary reports `decision=restore_summary_blocked` and records every blocking issue in both JSON and compact report form.

## Reviewer checklist

Before promoting restore executor evidence, confirm:

1. The ready restore decision is `restore_ready_dry_run`.
2. The expected-blocked decision, when supplied, is `restore_blocked`.
3. The summary declares no live-state changes and no raw telemetry reads.
4. The summary preserves manual invocation as a required boundary.
5. Blocking issue count is zero.

## Validation

Focused validation:

```bash
bash tests/test_host_vm_policy_restore_release_summary_static.sh
bash tests/run_static_security_checks.sh
```

## Rollback

Revert `host_vm_policy_restore_release_summary.py`, `tests/test_host_vm_policy_restore_release_summary_static.sh`, this document, the changelog entry, and the README navigation entry. No host, VM, package, firewall, service, IDS, dataset, or hypervisor state needs rollback.

## Follow-up work

- Wire the restore release summary into a hosted restore executor release evidence workflow after repeated green static validation.
- Feed restore summary output into the same aggregate posture gate as firstboot and IDS evidence.
- Add reviewer-facing release notes whenever restore expected-blocked semantics change.
