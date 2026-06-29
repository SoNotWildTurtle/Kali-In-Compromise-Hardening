# Firstboot final readiness contract seal

`firstboot_final_readiness_contract_seal.py` is a passive release-review helper that consumes only the aggregate `/var/log/firstboot_release_gate.final_readiness_manifest_smoke.summary.env` sidecar and emits derived contract-seal evidence for dashboards, ISO promotion review, and recovery handoff.

## Purpose

The helper extends the firstboot release-gate evidence chain with a final machine-readable seal. It validates that the upstream manifest smoke summary is shell-quoted, internally consistent, privacy scoped to aggregate evidence, and explicitly approved before the derived seal can pass.

## Security boundary

The helper is read-only and aggregate-only. It does not source shell content, inspect raw telemetry, read packet captures, open sockets, alter firewall rules, change services, mutate model or dataset files, approve restore execution, or modify host or VM state.

This follows the repository's secure-by-default direction and maps cleanly to NIST SP 800-53 Rev. 5 control themes for Audit and Accountability, Assessment/Authorization/Monitoring, Configuration Management, System and Communications Protection, System and Information Integrity, and Supply Chain Risk Management.

## Fail-closed behavior

The helper returns `deferred`/`stop` when the manifest smoke summary is missing, malformed, privacy-scope mismatched, blocker-inconsistent, expected-artifact-empty, marked pass while failed, or inconsistent with the expected `firstboot_final_readiness_manifest_smoke` component identity.

`--require-pass` exits non-zero when the derived seal is not approved so release gates can fail closed without bypassing the existing evidence chain.

## Outputs

Supported formats are text, JSON, Markdown, and optional shell-safe `.summary.env` sidecar output.

Example:

```bash
python3 firstboot_final_readiness_contract_seal.py \
  --input /var/log/firstboot_release_gate.final_readiness_manifest_smoke.summary.env \
  --format json \
  --output /var/log/firstboot_release_gate.final_readiness_contract_seal.json \
  --summary /var/log/firstboot_release_gate.final_readiness_contract_seal.summary.env
```

The summary keys use the `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*` prefix.

## Compatibility

The helper has no third-party Python dependencies and remains compatible with constrained firstboot, CI, and recovery contexts that can read the aggregate summary sidecar.

## Rollback

Rollback is removal of the optional helper from ISO packaging or release-gate refresh wiring. The existing final-readiness manifest smoke JSON, Markdown, and `.summary.env` artifacts remain authoritative.

## Follow-up work

- Package the helper into the custom ISO build.
- Wire best-effort JSON, Markdown, and `.summary.env` refresh into `firstboot_release_gate.service` after manifest smoke artifacts are generated.
- Add release-gate dashboard consumption for `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*` fields.
