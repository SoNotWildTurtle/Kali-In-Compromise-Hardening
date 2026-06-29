# Changelog fragment: firstboot operator verdict

## Added

- Added `firstboot_final_readiness_operator_verdict.py`, a passive aggregate-only handoff renderer for the final-readiness contract-seal smoke `.summary.env` sidecar.
- Packaged the operator verdict helper in custom ISO builds and wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` verdict artifacts after contract-seal smoke evidence is generated.
- Added static coverage for approved verdict generation, privacy-scope fail-closed behavior, packaging, firstboot service wiring, documentation, rollback notes, and NIST-aligned auditability language.

## Security

- The operator verdict helper validates only quoted aggregate `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_*` fields, emits derived `FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_*` evidence, and does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, or modify host/VM state.
- The `--require-pass` path exits non-zero when upstream smoke evidence is missing, malformed, privacy-scope mismatched, blocker-inconsistent, expected-artifact-empty, or marked pass while failed.

## Rollback

- Remove `firstboot_final_readiness_operator_verdict.py` from ISO packaging and remove its two `ExecStartPost=` lines from `firstboot_release_gate.service`. Contract-seal smoke JSON, Markdown, and `.summary.env` artifacts remain authoritative.
