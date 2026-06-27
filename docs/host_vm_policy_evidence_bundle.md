# Host VM Policy Evidence Bundle

`host_vm_policy_evidence_bundle.py` is a read-only review helper. It collects compact summaries from host VM policy attestation, policy verification, restore planning, approval checking, and NN IDS health evidence.

The utility is designed for defensive handoff and release review. It records paths, SHA-256 digests, selected status fields, review items, and one overall `pass`, `warn`, `review`, or `fail` result. It does not change firewall rules, systemd units, host settings, VM settings, IDS models, restore files, or approvals.

## Usage

```bash
sudo /usr/local/bin/host_vm_policy_evidence_bundle.py \
  --output /var/lib/host_vm_comm_guard/policy_evidence_bundle.json \
  --report /var/log/host_vm_policy_evidence_bundle.report
```

Use `--require-pass` when automation should stop on any review or failure signal.

```bash
sudo /usr/local/bin/host_vm_policy_evidence_bundle.py --require-pass
```

## Result meanings

- `pass`: required evidence exists, parses, and has no review signal.
- `warn`: required evidence exists, but optional evidence reports warnings.
- `review`: policy, restore, approval, or IDS evidence needs manual review.
- `fail`: required attestation or verification evidence is missing or malformed.

## Rollback

Remove the utility, its static test, this document, and the packaging entry in `build_custom_iso.sh`. The feature is additive and manual, so no deployed service needs to be disabled.
