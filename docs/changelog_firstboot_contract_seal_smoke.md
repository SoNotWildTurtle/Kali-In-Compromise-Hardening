# Changelog fragment: firstboot contract seal smoke

## Added

- Added `firstboot_final_readiness_contract_seal_smoke.py`, a passive aggregate-only smoke gate for the contract-seal `.summary.env` sidecar that validates the quoted `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*` contract without sourcing shell content.
- Packaged the contract-seal and contract-seal smoke helpers, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` seal artifacts, and documented approval, rollback, privacy, safe-default behavior, and static coverage.

## Security

- The contract-seal smoke helper is additive and passive: it validates only the quoted aggregate contract-seal summary sidecar, emits derived smoke evidence, and does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, or modify host/VM state.
- The `--require-pass` path exits non-zero when contract-seal evidence is missing, malformed, privacy-scope mismatched, internally inconsistent, blocker-inconsistent, expected-artifact-empty, or marked pass while failed.

## Rollback

Remove the optional smoke helper from ISO packaging and release-gate refresh wiring. Existing final-readiness contract-seal JSON, Markdown, and `.summary.env` artifacts remain authoritative.
