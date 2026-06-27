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

Use the optional freshness gate when firstboot or release reviewers need recent handoff artifacts before accepting an ISO promotion packet:

```bash
python3 host_vm_policy_firstboot_manifest.py \
  --max-artifact-age-minutes 60 \
  --require-ready
```

When omitted, `--max-artifact-age-minutes` preserves the previous behavior and does not block on artifact age.

## Output contract

The JSON manifest includes:

- `component`: always `host_vm_policy_firstboot_manifest`.
- `decision`: `approved` only when all required artifacts exist, parseable JSON artifacts are valid objects, both the handoff and receipt report ready status, and any enabled freshness policy passes.
- `release_gate`: `pass` or `stop` for CI, ISO promotion, or recovery workflows.
- `freshness_policy`: whether `--max-artifact-age-minutes` was enabled, the threshold used, and the future timestamp skew tolerance.
- `blockers`: missing artifacts, invalid JSON artifacts, deferred handoff/receipt readiness, stale artifact findings, future timestamp findings, or mtime read failures.
- `artifacts`: required artifact paths, presence, size, `mtime_utc`, `age_seconds`, and SHA-256 digests.
- `privacy_note`, `safe_default`, `rollback_note`, and `operator_next_steps` for reviewer handoff.

The Markdown report mirrors the same data for human review, including a freshness policy section and per-artifact timestamp/age summaries.

## Freshness gate behavior

`--max-artifact-age-minutes` is passive and metadata-only. It compares present artifact modification times to the current local system clock, adds `artifact_name:stale:<age>s><threshold>s` blockers for old artifacts, and adds `artifact_name:future_mtime:<timestamp>` blockers for timestamps more than five minutes in the future.

Missing artifacts are still reported by the existing required-artifact blockers. The freshness gate never reads raw logs or changes evidence files; it only records the existing filesystem metadata already used by the manifest.

## Privacy and security rationale

The helper is read-only. It records artifact metadata, aggregate decisions, and SHA-256 digests only. It does not read or embed raw telemetry, environment identifiers, credentials, private operator data, model files, datasets, host state, VM state, approval state, or recovery state.

`--require-ready` exits non-zero when required artifacts are missing, malformed, deferred, stale, or clock-skewed. This makes ISO promotion and firstboot handoff acceptance auditable without weakening existing validation.

## Compatibility

The helper uses only the Python standard library and is packaged into the custom ISO by `build_custom_iso.sh`. It is safe for Kali firstboot, release-gate, and recovery-review environments that already produce the host/VM policy evidence bundle and receipt artifacts.

The freshness gate is opt-in, so existing scripts that call the manifest helper without `--max-artifact-age-minutes` keep the previous readiness behavior.

## Rollback

Remove the generated manifest JSON/Markdown files, or revert the helper, packaging entry, tests, and documentation. Existing evidence bundle, receipt, handoff, host, VM, service, model, dataset, approval, and recovery state are not modified by this helper.

## Follow-up work

- Wire the manifest into a firstboot timer or release gate after enough real ISO runs confirm the artifact order.
- Add a combined dashboard view that includes NN IDS posture manifests and host/VM policy handoff manifests without exposing sensitive telemetry.
- Consider a separate `--warn-artifact-age-minutes` threshold for advisory-only operator review once field evidence clarifies expected ISO timing variance.
