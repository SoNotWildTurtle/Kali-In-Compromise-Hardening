# Host/VM Policy Evidence Bundle

`host_vm_policy_evidence_bundle.py` creates a read-only, privacy-safe review bundle that links the host/VM policy attestation, policy verification result, restore plan, approval check, and NN IDS evidence into one machine-readable artifact.

## Why this exists

The hardening suite already creates separate artifacts for policy attestation, drift verification, restore planning, approval validation, restore execution review, and NN IDS health. During incident review or release gating, an operator needs one compact handoff object that answers:

- Which defensive evidence files existed at review time?
- Which components need manual review?
- Did any required evidence fail closed?
- Can the bundle be shared without embedding full policy JSON or approval details?

This tool answers those questions without changing firewall rules, systemd state, host state, VM state, IDS models, approvals, or restore files.

## Example

```bash
sudo /usr/local/bin/host_vm_policy_evidence_bundle.py \
  --output /var/lib/host_vm_comm_guard/policy_evidence_bundle.json \
  --report /var/log/host_vm_policy_evidence_bundle.report
```

Use `--require-pass` in release-gate or handoff automation when a non-passing bundle should stop the workflow:

```bash
sudo /usr/local/bin/host_vm_policy_evidence_bundle.py --require-pass
```

## Status semantics

- `pass`: required evidence exists, parses, and no review/warning signals were detected.
- `warn`: required evidence is present, but optional telemetry reports warnings.
- `review`: restore, approval, NN IDS, or policy verification evidence signals manual review.
- `fail`: required attestation or verification evidence is missing or malformed.

## Privacy and safety

The bundle stores component paths, SHA-256 digests, timestamps, selected non-sensitive summary keys, and the final triage status. It intentionally does not embed full source JSON documents, signatures, tokens, passwords, private keys, credentials, or approval payloads. The compact report is line-oriented for easy copying into incident notes.

## Rollback

This feature is additive and manual. Roll back by removing `host_vm_policy_evidence_bundle.py`, this document, and the static test, then remove the packaging entry from `build_custom_iso.sh`. No live system policy is modified by the utility.

## Follow-up work

- Wire the bundle into aggregate posture release gates once operators agree on pass/warn/review thresholds.
- Add an optional HTML renderer for local incident handoff review.
- Include detached signature verification of bundle files after the local signing policy is finalized.
