# Host/VM policy restore executor

`host_vm_policy_restore_execute.py` is the final, manual step in the host/VM communication recovery chain. It is intentionally conservative: by default it performs a dry-run only, and it refuses to restore anything unless the restore plan and approval validation both indicate that a human-reviewed restore is eligible.

## Recovery chain

1. `host_vm_policy_attest.py` records local policy evidence.
2. `host_vm_policy_verify.py` compares current evidence with the known-good baseline.
3. `host_vm_policy_restore_plan.py` identifies review-only restore candidates.
4. `host_vm_policy_approval_check.py` validates a short-lived human approval file.
5. `host_vm_policy_restore_execute.py` performs a dry-run unless explicitly invoked with `--execute`.

## Safety properties

- Requires `policy_restore_plan.json` decision `manual_restore_review_required`.
- Requires `policy_restore_approval_check.json` decision `approval_valid`.
- Requires approval validation freshness; default maximum age is 15 minutes.
- Restores only allowlisted files: `/etc/host_vm_comm_guard.conf` and `/etc/nftables.d/host_vm_comm_guard.nft`.
- Verifies known-good source hashes from the restore plan before copying.
- Saves pre-restore backups under `/var/lib/host_vm_comm_guard/pre_restore_backups`.
- Does not reload services unless `--reload-after-restore` is also passed.

## Dry-run

```bash
sudo /usr/local/bin/host_vm_policy_restore_execute.py
```

A successful dry-run returns `restore_ready_dry_run` and writes:

- `/var/lib/host_vm_comm_guard/policy_restore_execute.json`
- `/var/log/host_vm_policy_restore_execute.report`

## Manual execution

Only run this from a local console or otherwise recoverable session:

```bash
sudo /usr/local/bin/host_vm_policy_approval_check.py
sudo /usr/local/bin/host_vm_policy_restore_execute.py --execute
```

To also validate/reload affected policy after restoring:

```bash
sudo /usr/local/bin/host_vm_policy_restore_execute.py --execute --reload-after-restore
```

The executor deliberately does not run from a timer. The service unit exists for controlled one-shot invocation and is not enabled by first boot.

## Test coverage

`tests/test_host_vm_policy_restore_execute_integration.sh` covers realistic dry-run approval, stale-approval refusal, known-good hash mismatch refusal, and the approved execute branch. The execute-branch test imports the executor and monkeypatches copy/reload functions into a temporary shadow root, so it validates the restore decision and action metadata without writing to live `/etc` or invoking `systemctl`/`nft`.

`tests/test_host_vm_policy_restore_execute_integration_static.sh` runs that integration fixture from the repo-wide static gate so the release checks fail closed if the manual executor path regresses.

## Rationale

Recent secure rollback research argues that legitimate recovery needs explicit authorization, freshness checks, audit output, and mediated state transitions rather than blind rollback. The executor follows that pattern for local Kali host/VM communication policy recovery while preserving a safe dry-run default.
