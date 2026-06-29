# Firstboot final readiness operator bundle

`firstboot_final_readiness_operator_bundle.py` is a passive release-handoff helper that consumes only the aggregate `/var/log/firstboot_release_gate.final_readiness_operator_verdict.summary.env` sidecar and emits derived operator-bundle evidence for dashboards, ISO promotion review, and recovery handoff.

## Purpose

The helper extends the firstboot release-gate evidence chain with a compact machine-readable bundle index downstream of the operator verdict. It validates that the upstream `FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_*` summary is shell-quoted, internally consistent, privacy scoped to aggregate evidence, and explicitly set to `promote` before the derived bundle can pass.

This gives release dashboards a single `ready`/`hold` bundle field while preserving the stronger upstream operator verdict, contract-seal smoke, manifest smoke, freshness, and release-gate artifacts as the authoritative evidence chain.

## Security boundary

The helper is read-only and aggregate-only. It does not source shell content, inspect raw telemetry, read packet captures, open sockets, alter firewall rules, change services, mutate model or dataset files, approve restore execution, or modify host or VM state.

The design aligns with secure-by-default governance and evidence-chain review patterns from NIST Cybersecurity Framework 2.0 functions Govern, Identify, Protect, Detect, Respond, and Recover; NIST SP 800-53 Rev. 5 control themes for auditability, configuration management, system and communications protection, system and information integrity, and supply-chain risk management; and CISA Secure by Design expectations for safe defaults, transparent evidence, and reversible operation.

## Fail-closed behavior

The operator bundle returns `hold` with `deferred`/`stop` when the operator-verdict summary is missing, malformed, privacy-scope mismatched, blocker-inconsistent, expected-artifact-empty, marked pass while failed, marked `promote` without a passing release gate, or inconsistent with the expected `firstboot_final_readiness_operator_verdict` component identity.

`--require-pass` exits non-zero when the derived bundle is not approved so release gates can fail closed without bypassing the existing evidence chain.

## Outputs

Supported formats are text, JSON, Markdown, and optional shell-safe `.summary.env` sidecar output.

Example operator bundle:

```bash
python3 firstboot_final_readiness_operator_bundle.py \
  --input /var/log/firstboot_release_gate.final_readiness_operator_verdict.summary.env \
  --format json \
  --output /var/log/firstboot_release_gate.final_readiness_operator_bundle.json \
  --summary /var/log/firstboot_release_gate.final_readiness_operator_bundle.summary.env
```

The operator bundle summary keys use the `FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_*` prefix.

## Packaging and firstboot wiring

Custom ISO builds package the helper. `firstboot_release_gate.service` refreshes operator-bundle JSON, Markdown, and `.summary.env` artifacts after operator-verdict artifacts are generated.

This keeps firstboot, recurring timer refreshes, recovery handoffs, and release dashboards on the same additive evidence chain without introducing enforcement, persistence, network access, or host/VM mutation.

## Compatibility

The helper has no third-party Python dependencies and remains compatible with constrained firstboot, CI, and recovery contexts that can read the aggregate summary sidecars.

## Rollback

Rollback is removal of the optional helper from ISO packaging or release-gate refresh wiring. The existing operator-verdict JSON, Markdown, and `.summary.env` artifacts remain authoritative.

## Follow-up work

- Add release dashboard consumption for `FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_*` fields.
- Extend final release bundle manifests to include the operator-bundle artifacts as optional evidence once downstream consumers are ready.
