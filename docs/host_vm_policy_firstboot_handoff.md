# Host VM Policy Firstboot Handoff

`host_vm_policy_firstboot_handoff.py` composes the existing policy evidence bundle and receipt utilities into one privacy-safe handoff artifact for firstboot review, release review, or recovery review.

The helper is additive and read-only. It writes JSON and Markdown review artifacts and does not change live machine state, approval state, restore state, model files, or datasets.

## Usage

Generate the default bundle, receipt, and handoff index:

```bash
sudo /usr/local/bin/host_vm_policy_firstboot_handoff.py
```

Use it as an explicit gate:

```bash
sudo /usr/local/bin/host_vm_policy_firstboot_handoff.py --require-ready
```

Allow warning-only evidence only when an operator has explicitly accepted the warning state:

```bash
sudo /usr/local/bin/host_vm_policy_firstboot_handoff.py \
  --allow-warning-approval \
  --require-ready
```

## Generated artifacts

Default outputs:

- `/var/lib/host_vm_comm_guard/policy_evidence_bundle.json`
- `/var/log/host_vm_policy_evidence_bundle.report`
- `/var/lib/host_vm_comm_guard/policy_evidence_bundle_receipt.json`
- `/var/log/host_vm_policy_evidence_bundle_receipt.md`
- `/var/log/host_vm_policy_firstboot_handoff.json`
- `/var/log/host_vm_policy_firstboot_handoff.md`

The handoff index records the receipt decision, gate result, bundle and receipt SHA-256 digests, review items, operator actions, privacy notes, and rollback notes.

## Privacy and security rationale

The helper uses aggregate evidence and receipt metadata only. It does not embed raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, or datasets. It does not open network sockets or execute external commands.

`--require-ready` exits non-zero when the receipt is deferred, making it suitable for CI, release, firstboot promotion, or recovery validation gates. The default path remains non-destructive and review-only.

## Compatibility

This helper composes the existing `host_vm_policy_evidence_bundle.py` and `host_vm_policy_evidence_bundle_receipt.py` contracts. Existing consumers can continue reading either upstream artifact directly; the firstboot handoff index is a downstream convenience artifact.

## Rollback

Delete generated handoff artifacts and revert this helper, its test, packaging entry, changelog entry, and this document. No deployed service must be disabled because the helper is passive and only writes review artifacts.

## Follow-up work

- Optionally call this helper from `firstboot.sh` after policy verification and restore planning once the firstboot flow is ready for non-blocking handoff emission.
- Add a release workflow step that runs `--require-ready` against fixture artifacts before publishing custom ISO outputs.
- Add signed artifact support after repository-level signing policy is defined.
