# Host/VM Firstboot Release Readiness Summary

`host_vm_policy_firstboot_release_summary.py` builds a compact, machine-readable reviewer handoff from passive firstboot release receipt evidence. It is designed to sit one layer above the handoff gate and release receipt so release reviewers can compare:

- a `release_receipt_ready` artifact from the strict release-ready handoff path, and
- an optional `release_receipt_blocked` artifact from the expected-blocked synthetic fixture.

The summary is aggregate-only. It does not read raw telemetry, packet captures, hostnames, usernames, credentials, model binaries, datasets, private keys, tokens, logs, live service state, firewall state, package state, or hypervisor state. It only validates receipt JSON fields already emitted by the passive release receipt workflow or local reviewer fixtures.

## Threat-model rationale

The firstboot handoff workflow is intentionally staged before live packaging or firstboot mutation. The summary helps reviewers verify that the release-ready path is green while the expected-negative fixture still fails closed. That makes it easier to distinguish an intentional blocked fixture from a real workflow failure without weakening strict release promotion.

The summary is safe-by-default:

- `changes_live_state=false`
- `reads_raw_telemetry=false`
- `aggregate_evidence_only=true`
- rollback requires reverting summary files only
- `--strict` exits non-zero unless the summary is internally consistent

## Usage

Build a summary from a ready receipt:

```bash
python3 host_vm_policy_firstboot_release_summary.py \
  /tmp/firstboot-handoff-gate/firstboot_release_receipt.json \
  --output /tmp/firstboot-handoff-gate/firstboot_release_summary.json \
  --report /tmp/firstboot-handoff-gate/firstboot_release_summary.report \
  --strict
```

Build a summary that also compares expected-blocked evidence:

```bash
python3 host_vm_policy_firstboot_release_summary.py \
  /tmp/firstboot-handoff-gate/firstboot_release_receipt.json \
  --expected-blocked-receipt /tmp/firstboot-handoff-gate-blocked/firstboot_release_receipt.blocked.json \
  --output /tmp/firstboot-handoff-gate/firstboot_release_summary.json \
  --report /tmp/firstboot-handoff-gate/firstboot_release_summary.report \
  --strict
```

A ready summary reports:

```text
decision=summary_ready
summary_ready=true
ready_receipt_decision=release_receipt_ready
expected_blocked_decision=release_receipt_blocked
blocking_issue_count=0
```

A blocked summary reports `decision=summary_blocked` and records each blocking issue in JSON and compact report form.

## Hosted workflow artifacts

The `Firstboot Handoff Release Gate` workflow now builds the release summary after both the ready receipt and expected-blocked receipt fixture are generated. The hosted evidence bundle includes:

- `/tmp/firstboot-handoff-gate/firstboot_release_summary.json`
- `/tmp/firstboot-handoff-gate/firstboot_release_summary.report`

Those artifacts are uploaded with `firstboot-handoff-gate-evidence` so reviewers can verify the ready path, the expected-negative fixture decision, and zero summary blocking issues from a single machine-readable handoff.

## Reviewer handoff checklist

Before using the summary as release evidence, reviewers should confirm:

1. The ready receipt decision is `release_receipt_ready`.
2. If the expected-blocked fixture is present, its decision is `release_receipt_blocked`.
3. The summary declares no live-state changes and no raw telemetry reads.
4. Blocking issue count is zero for the ready summary.
5. Hosted workflow artifacts include both ready evidence and expected-negative evidence.

## Validation

Focused validation:

```bash
bash tests/test_host_vm_policy_firstboot_release_summary_static.sh
bash tests/test_firstboot_handoff_release_gate_workflow_static.sh
bash tests/run_static_security_checks.sh
```

## Rollback

Revert `host_vm_policy_firstboot_release_summary.py`, `tests/test_host_vm_policy_firstboot_release_summary_static.sh`, this document, the changelog entry, and the summary-specific workflow wiring. No host, VM, package, firewall, service, IDS, dataset, or hypervisor state needs rollback.

## Follow-up work

- Feed restore executor and IDS aggregate release evidence into the same summary once those receipts expose compatible ready and expected-blocked semantics.
- Add reviewer-facing release notes whenever expected-blocked summary semantics change.
- Keep live firstboot packaging gated behind repeated green hosted summaries and explicit human review.
