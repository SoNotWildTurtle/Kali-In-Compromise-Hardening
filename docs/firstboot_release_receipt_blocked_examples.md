# Firstboot Release Receipt Blocked Examples

This note documents expected blocked outcomes for `host_vm_policy_firstboot_release_receipt.py`. The examples are passive and use synthetic aggregate gate evidence only; they do not read raw telemetry, collect credentials, install packages, start services, change firewall rules, or mutate host or VM state.

## Why blocked examples exist

Release receipts are useful only when reviewers can tell the difference between:

- a valid release-ready handoff;
- an intentionally blocked handoff that proves fail-closed behavior; and
- a malformed artifact that should never be promoted.

The static test now covers both a normal blocked gate and a malformed gate so future workflow changes preserve this distinction.

## Normal blocked gate

A normal blocked gate comes from `host_vm_policy_firstboot_handoff_gate.py`, remains aggregate-only and non-mutating, but reports a failed check such as invalid profile validation.

Expected receipt behavior:

- `decision` is `release_receipt_blocked`.
- strict mode exits non-zero.
- `blocking_issues` includes the non-ready gate decision and the failing check name.
- report output includes one `issue=` line per blocker.

## Malformed gate

A malformed gate may be missing required fields, reference an unexpected gate name, claim live-state mutation, claim raw telemetry access, or provide a malformed `checks` payload.

Expected receipt behavior:

- `decision` is `release_receipt_blocked`.
- non-strict mode still writes JSON and report artifacts for review.
- strict mode exits non-zero.
- blockers are explicit enough for reviewers to distinguish schema or safety problems from ordinary profile-validation failure.

## Operator handoff

When a hosted run includes a blocked receipt artifact, reviewers should inspect `blocking_issues` before deciding whether the result is an expected negative fixture, a real release blocker, or a malformed artifact. Do not promote firstboot packaging or live wiring from any receipt unless the receipt decision is `release_receipt_ready` and the source handoff gate is `release_ready`.

## Rollback

This documentation and the related static-test fixture are additive. Revert this file and the malformed-gate fixture additions in `tests/test_host_vm_policy_firstboot_release_receipt_static.sh` to roll back the increment. No live system state requires rollback.

## Follow-up

- Add a compact blocked fixture artifact to the hosted workflow once the aggregate release gate can publish expected-negative artifacts without making the workflow fail.
- Feed receipt blockers into a broader release readiness summary with restore executor and IDS audit evidence.
