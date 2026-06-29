# Unreleased

## Added

- Added `firstboot_final_readiness_operator_bundle_smoke.py`, a passive aggregate-only smoke helper for the operator-bundle `.summary.env` sidecar that emits JSON, Markdown, and shell-safe `FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_*` evidence.
- Packaged the smoke helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` operator-bundle smoke artifacts, and added static coverage for pass, fail-closed mismatch behavior, documentation, rollback guidance, and service wiring.

## Security

- The operator-bundle smoke helper is additive and passive: it validates only quoted aggregate operator-bundle summary fields, fails closed on malformed or inconsistent evidence, and does not inspect raw telemetry, open sockets, alter firewall rules, change services, mutate models or datasets, approve restores, or modify host/VM state.
