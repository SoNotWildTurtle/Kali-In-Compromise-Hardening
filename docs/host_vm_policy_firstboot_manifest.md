# Host VM Firstboot Handoff Manifest

`host_vm_policy_firstboot_manifest.py` is a passive release and firstboot helper that records which host/VM policy handoff artifacts were produced, whether the handoff is ready, and how reviewers can reproduce artifact provenance by hash.

It is intended to run after `host_vm_policy_firstboot_handoff.py` has generated the evidence bundle, receipt, firstboot index, and Markdown handoff. The manifest gives ISO reviewers, recovery operators, and release gates a single artifact inventory instead of forcing them to manually compare several files.

## Usage

```bash
python3 host_vm_policy_firstboot_manifest.py \
  --bundle /var/lib/host_vm_comm_guard/policy_evidence_bundle.json \
  --bundle-report /var/log/host_vm_policy_evidence_bundle.report \
  --receipt /var/lib/host_vm_comm_guard/policy_evidence_bundle_receipt.json \
  --receipt-markdown /var/log/host_vm_policy_evidence_bundle_receipt.md \
  --handoff-index /var/log/host_vm_policy_firstboot_handoff.json \
  --handoff-markdown /var/log/host_vm_policy_firstboot_handoff.md \
  --manifest /var/log/host_vm_policy_firstboot_manifest.json \
  --markdown /var/log/host_vm_policy_firstboot_manifest.md \
  --require-ready
```

The default paths match the firstboot handoff helper, so the shorter form is usually enough after firstboot evidence exists:

```bash
python3 host_vm_policy_firstboot_manifest.py --require-ready
```

## Output contract

The JSON manifest includes:

- `component`: always `host_vm_policy_firstboot_manifest`.
- `decision`: `approved` only when all required artifacts exist, parseable JSON artifacts are valid objects, and both the handoff and receipt report ready status.
- `release_gate`: `pass` or `stop` for CI, ISO promotion, or recovery workflows.
- `blockers`: missing artifacts, invalid JSON artifacts, or deferred handoff/receipt readiness.
- `artifacts`: required artifact paths, presence, size, and SHA-256 digests.
- `privacy_note`, `safe_default`, `rollback_note`, and `operator_next_steps` for reviewer handoff.

The Markdown report mirrors the same data for human review.

## Privacy and security rationale

The helper is read-only. It records artifact metadata, aggregate decisions, and SHA-256 digests only. It does not read or embed raw telemetry, environment identifiers, credentials, private operator data, model files, datasets, host state, VM state, approval state, or recovery state.

`--require-ready` exits non-zero when required artifacts are missing, malformed, or deferred. This makes ISO promotion and firstboot handoff acceptance auditable without weakening existing validation.

## Compatibility

The helper uses only the Python standard library and is packaged into the custom ISO by `build_custom_iso.sh`. It is safe for Kali firstboot, release-gate, and recovery-review environments that already produce the host/VM policy evidence bundle and receipt artifacts.

## Rollback

Remove the generated manifest JSON/Markdown files, or revert the helper, packaging entry, tests, and documentation. Existing evidence bundle, receipt, handoff, host, VM, service, model, dataset, approval, and recovery state are not modified by this helper.

## Follow-up work

- Wire the manifest into a firstboot timer or release gate after enough real ISO runs confirm the artifact order.
- Add optional freshness thresholds once firstboot artifact timestamps are stable across installer and live ISO flows.
- Add a combined dashboard view that includes NN IDS posture manifests and host/VM policy handoff manifests without exposing sensitive telemetry.
