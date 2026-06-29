# Firstboot final readiness contract seal

`firstboot_final_readiness_contract_seal.py` is a passive release-review helper that consumes only the aggregate `/var/log/firstboot_release_gate.final_readiness_manifest_smoke.summary.env` sidecar and emits derived contract-seal evidence for dashboards, ISO promotion review, and recovery handoff.

`firstboot_final_readiness_contract_seal_smoke.py` is the follow-up passive smoke gate for that contract-seal `.summary.env` sidecar. It validates the generated `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*` fields before downstream tooling treats the seal as handoff-ready.

`firstboot_final_readiness_operator_verdict.py` is the final passive handoff renderer for the contract-seal smoke `.summary.env` sidecar. It converts the validated `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_*` fields into a compact operator verdict, JSON evidence, Markdown evidence, and a shell-safe `FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_*` summary sidecar.

## Purpose

The helper extends the firstboot release-gate evidence chain with a final machine-readable seal. It validates that the upstream manifest smoke summary is shell-quoted, internally consistent, privacy scoped to aggregate evidence, and explicitly approved before the derived seal can pass.

The smoke helper adds a second aggregate-only assertion layer for formatting-sensitive regressions: missing keys, unquoted values, mismatched privacy scope, invalid pass/deferred decisions, blocker count inconsistencies, and missing expected-artifact counts fail closed as `deferred`/`stop`.

The operator verdict helper gives release dashboards and human handoffs a single `promote`/`hold` field without weakening the underlying smoke gate. It is intentionally downstream of the contract-seal smoke helper so brittle formatting, privacy scope, blocker-count, and artifact-count regressions are caught before a human-readable verdict is emitted.

## Security boundary

All three helpers are read-only and aggregate-only. Each helper does not source shell content, inspect raw telemetry, read packet captures, open sockets, alter firewall rules, change services, mutate model or dataset files, approve restore execution, or modify host or VM state.

This follows the repository's secure-by-default direction and maps cleanly to NIST SP 800-53 Rev. 5 control themes for Audit and Accountability, Assessment/Authorization/Monitoring, Configuration Management, System and Communications Protection, System and Information Integrity, and Supply Chain Risk Management.

## Fail-closed behavior

The contract-seal helper returns `deferred`/`stop` when the manifest smoke summary is missing, malformed, privacy-scope mismatched, blocker-inconsistent, expected-artifact-empty, marked pass while failed, or inconsistent with the expected `firstboot_final_readiness_manifest_smoke` component identity.

The smoke helper returns `deferred`/`stop` when the contract-seal summary is missing, malformed, privacy-scope mismatched, blocker-inconsistent, expected-artifact-empty, marked pass while failed, or inconsistent with the expected `firstboot_final_readiness_contract_seal` component identity.

The operator verdict helper returns `hold` with `deferred`/`stop` when the contract-seal smoke summary is missing, malformed, privacy-scope mismatched, blocker-inconsistent, expected-artifact-empty, marked pass while failed, or inconsistent with the expected `firstboot_final_readiness_contract_seal_smoke` component identity.

`--require-pass` exits non-zero when the derived seal, smoke evidence, or operator verdict is not approved so release gates can fail closed without bypassing the existing evidence chain.

## Outputs

Supported formats are text, JSON, Markdown, and optional shell-safe `.summary.env` sidecar output.

Example contract seal:

```bash
python3 firstboot_final_readiness_contract_seal.py \
  --input /var/log/firstboot_release_gate.final_readiness_manifest_smoke.summary.env \
  --format json \
  --output /var/log/firstboot_release_gate.final_readiness_contract_seal.json \
  --summary /var/log/firstboot_release_gate.final_readiness_contract_seal.summary.env
```

Example smoke validation:

```bash
python3 firstboot_final_readiness_contract_seal_smoke.py \
  --input /var/log/firstboot_release_gate.final_readiness_contract_seal.summary.env \
  --format json \
  --output /var/log/firstboot_release_gate.final_readiness_contract_seal_smoke.json \
  --summary /var/log/firstboot_release_gate.final_readiness_contract_seal_smoke.summary.env
```

Example operator verdict:

```bash
python3 firstboot_final_readiness_operator_verdict.py \
  --input /var/log/firstboot_release_gate.final_readiness_contract_seal_smoke.summary.env \
  --format json \
  --output /var/log/firstboot_release_gate.final_readiness_operator_verdict.json \
  --summary /var/log/firstboot_release_gate.final_readiness_operator_verdict.summary.env
```

The contract-seal summary keys use the `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*` prefix. The smoke summary keys use the `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_*` prefix. The operator verdict summary keys use the `FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_*` prefix.

## Packaging and firstboot wiring

Custom ISO builds package all three helpers. `firstboot_release_gate.service` refreshes contract-seal JSON, Markdown, `.summary.env`, smoke JSON, smoke Markdown, smoke `.summary.env`, operator-verdict JSON, operator-verdict Markdown, and operator-verdict `.summary.env` artifacts after the final-readiness manifest smoke artifacts are generated.

This keeps firstboot, recurring timer refreshes, recovery handoffs, and release dashboards on the same additive evidence chain without introducing enforcement, persistence, network access, or host/VM mutation.

## Compatibility

The helpers have no third-party Python dependencies and remain compatible with constrained firstboot, CI, and recovery contexts that can read the aggregate summary sidecars.

## Rollback

Rollback is removal of the optional helpers from ISO packaging or release-gate refresh wiring. The existing final-readiness manifest smoke JSON, Markdown, contract-seal smoke JSON, Markdown, and `.summary.env` artifacts remain authoritative.

## Follow-up work

- Add release-gate dashboard consumption for `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*`, `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_*`, and `FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_*` fields.
- Extend the final release bundle manifest to list operator-verdict artifacts as optional evidence once dashboards consume them.
