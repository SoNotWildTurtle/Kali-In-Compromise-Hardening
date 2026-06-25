# Host/VM Policy Restore Approval Check

`host_vm_policy_approval_check.py` adds a validation-only approval gate after the host/VM policy restore planner. It does not restore files and does not alter firewall, nftables, systemd, model, host, or VM state.

## Why this exists

The restore planner intentionally stops at `manual_restore_review_required`. This approval checker validates that a local human reviewed the plan before any later restore workflow is allowed to consume the approval result. This keeps recovery reviewable, reversible, and console-safe.

Recent virtualization research continues to show that guest/host boundaries can fail through cross-domain hypervisor exploitation and side-channel leakage. A restore path should therefore be deliberately review-gated instead of automatic. Recent cybersecurity ML research also shows that IDS model robustness and explainability can drift, so restore approval must preserve the audit trail rather than erase evidence.

## Inputs

Default paths:

- Restore plan: `/var/lib/host_vm_comm_guard/policy_restore_plan.json`
- Human approval: `/var/lib/host_vm_comm_guard/policy_restore_approval.json`
- Optional Ed25519 public key: `/etc/host_vm_comm_guard.restore_approval.ed25519.pub`
- Result: `/var/lib/host_vm_comm_guard/policy_restore_approval_check.json`
- Report: `/var/log/host_vm_policy_approval_check.report`

## Approval requirements

The checker accepts an approval only when all of the following are true:

- Restore plan decision is `manual_restore_review_required`.
- Approval has `approved: true`.
- Approval purpose is `host_vm_policy_restore`.
- Approval baseline hash matches the restore plan baseline hash.
- Reviewer is named and is not the template placeholder.
- Review note documents the rationale.
- `reviewed_utc` and `expires_utc` use `YYYY-MM-DDTHH:MM:SSZ`.
- Approval is no older than 24 hours and expires within 24 hours.
- If a public key is configured, the approval carries a valid Ed25519 signature over the canonical approval payload.

## Create a safe template

```bash
sudo /usr/local/bin/host_vm_policy_approval_check.py --write-template
```

The template always writes `approved: false`. A reviewer must edit it locally after checking console access, the restore plan, the known-good manifest, current attestation drift, and the NN IDS audit/gate reports.

## Result decisions

- `approval_valid`: approval is valid for a later restore workflow to consider.
- `approval_rejected`: approval is missing, stale, unsigned when a key is required, mismatched, or otherwise unsafe.
- `template_written`: safe approval template was written.

## Safety notes

This component is intentionally non-mutating. A valid approval is not a restore action. Future restore tooling must still check this result, re-check hashes immediately before acting, keep rollback copies, and prefer local console execution.
