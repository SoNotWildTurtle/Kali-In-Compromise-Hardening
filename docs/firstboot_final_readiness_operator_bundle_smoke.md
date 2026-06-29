# Firstboot final readiness operator bundle smoke

`firstboot_final_readiness_operator_bundle_smoke.py` is a passive smoke validator for the aggregate operator-bundle `.summary.env` sidecar. It gives release dashboards and recovery handoff flows a final, compact pass/hold signal for the operator-bundle layer without sourcing shell content or changing host/VM state.

## Purpose

The helper validates the downstream `FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_*` fields after the operator bundle is generated. It confirms that the bundle is shell-quoted, internally consistent, privacy scoped to aggregate operator-bundle evidence, linked to the expected upstream operator-verdict source, and marked `ready` only when the release gate is passing.

This complements the stronger upstream firstboot final-readiness, manifest, contract-seal, operator-verdict, and operator-bundle helpers. The smoke layer is intentionally narrow: it checks the handoff summary contract so release automation can fail closed on malformed or inconsistent final bundle evidence.

## Security boundary

The helper is read-only and aggregate-only. It does not source shell content, inspect raw telemetry, read packet captures, open sockets, alter firewall rules, change services, mutate model or dataset files, approve restore execution, or modify host or VM state.

The design follows secure-by-default evidence-chain review expectations: fail closed on missing or inconsistent release evidence, keep verification auditable, preserve rollback, and avoid broad enforcement changes in firstboot handoff code.

## Fail-closed behavior

The operator-bundle smoke helper returns `hold` with `stop` when the operator-bundle summary is missing, malformed, uses unexpected keys, has unquoted values, reports a `ready` verdict without a passing release gate, reports blockers inconsistently, references the wrong source component, or changes the expected aggregate-only privacy boundary.

`--require-pass` exits non-zero when the smoke verdict is not passing so release gates can reject malformed handoff evidence without bypassing existing checks.

## Outputs

Supported formats are text, JSON, Markdown, and optional shell-safe `.summary.env` sidecar output.

Example:

```bash
python3 firstboot_final_readiness_operator_bundle_smoke.py \
  --input /var/log/firstboot_release_gate.final_readiness_operator_bundle.summary.env \
  --format json \
  --output /var/log/firstboot_release_gate.final_readiness_operator_bundle_smoke.json \
  --summary /var/log/firstboot_release_gate.final_readiness_operator_bundle_smoke.summary.env \
  --require-pass
```

The smoke summary keys use the `FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_*` prefix.

## Packaging and firstboot wiring

Custom ISO builds package the smoke helper. `firstboot_release_gate.service` refreshes operator-bundle smoke JSON, Markdown, and `.summary.env` artifacts immediately after operator-bundle JSON and Markdown are generated.

## Compatibility

The helper has no third-party Python dependencies and remains compatible with constrained firstboot, CI, and recovery contexts that can read aggregate summary sidecars.

## Rollback

Rollback is removal of this optional smoke helper from ISO packaging or release-gate refresh wiring. The operator-bundle JSON, Markdown, and `.summary.env` artifacts remain available and the upstream operator-verdict evidence remains authoritative.

## Follow-up work

- Add dashboard consumption for `FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_*` fields.
- Include operator-bundle smoke artifacts in a future final release bundle manifest once downstream consumers are ready.
