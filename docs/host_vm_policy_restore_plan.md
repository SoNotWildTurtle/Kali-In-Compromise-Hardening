# Host/VM policy restore planning

`host_vm_policy_restore_plan.py` adds a review-only recovery layer after policy attestation and verification. It does not alter nftables, systemd, IDS models, or host state. Its job is to preserve known-good copies of the critical host/VM communication policy files and produce a precise recovery plan when `host_vm_policy_verify.py` reports `restore_review`.

## Purpose

The hardening suite now has an attestation chain:

1. `host_vm_comm_guard.sh` creates the host/VM communication policy.
2. `host_vm_policy_attest.py` records local evidence.
3. `host_vm_policy_verify.py` compares evidence against a known-good baseline.
4. `host_vm_policy_restore_plan.py` prepares review-only recovery guidance.

This follows the project rule that recovery must be auditable and reversible. A compromised or misconfigured VM should not blindly rewrite firewall policy without review, local console access, and a confirmed recovery path.

## Outputs

Default outputs:

- `/var/lib/host_vm_comm_guard/known_good/` stores captured known-good copies.
- `/var/lib/host_vm_comm_guard/known_good/manifest.json` records hashes for the copies.
- `/var/lib/host_vm_comm_guard/policy_restore_plan.json` records the current review plan.
- `/var/log/host_vm_policy_restore_plan.report` provides a compact text summary.

## ISO packaging

The ISO build now requires and packages:

- `host_vm_policy_restore_plan.py`
- `host_vm_policy_restore_plan.service`
- `host_vm_policy_restore_plan.timer`

Keeping the restore planner in `build_custom_iso.sh` prevents a gap where verification reports `restore_review` but the installed VM lacks the tool that tells the operator exactly which reviewed policy files would need attention.

## First boot

After final attestation and baseline verification, first boot captures the known-good policy state and writes an initial plan:

```bash
/usr/local/bin/host_vm_policy_restore_plan.py --capture-known-good
/usr/local/bin/host_vm_policy_restore_plan.py
```

If no restore is needed, the plan decision is `no_restore_needed`. The timer is also enabled so future verification drift produces a fresh review plan without changing live policy.

## Timer behavior

The timer reruns the planner periodically. If the verifier later reports `restore_review`, the planner compares current policy files against the known-good copies and reports one of:

- `manual_restore_review_required`
- `restore_blocked_missing_known_good`
- `already_restored`
- `no_restore_needed`

## Smoke and regression validation

`vm_smoke_check.sh` now validates restore planner installation, timer presence, firstboot logs, the compact report, the JSON plan, and the known-good manifest. `tests/test_restore_planner_wiring_static.sh` prevents future changes from accidentally omitting the planner from ISO packaging, firstboot, smoke validation, or systemd sandboxing.

## Recovery posture

The plan includes an approval template but intentionally performs no live restoration. Operators should review the verifier output, review the restore plan, confirm local recovery access, take a current backup or VM snapshot, validate candidate policy files, and only then make any manual recovery change through the existing guard workflow.

This keeps restoration defensive, explicit, and auditable.

## Research basis

Recent virtualization research continues to emphasize that guest/host boundaries can fail in subtle ways, so restore decisions should not assume the guest is trustworthy. Recent NIDS research also highlights drift, explainability drift, and robustness degradation, which is why the plan preserves the NN IDS audit and verification chain rather than bypassing it.
