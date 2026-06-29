# Changelog fragment: firstboot contract seal

## Added

- Added `firstboot_final_readiness_contract_seal.py`, a passive aggregate-only release-gate helper that validates the quoted `FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_*` summary contract and emits derived `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*` evidence.
- Added `docs/firstboot_final_readiness_contract_seal.md` and static coverage for compile validation, privacy-scope tokens, fail-closed release-gate behavior, safe defaults, rollback notes, and NIST SP 800-53 Rev. 5 mapping language.

## Security

- The contract seal helper is additive and passive: it validates only the aggregate final-readiness manifest smoke sidecar, does not source shell content, does not inspect raw telemetry, does not open sockets, does not change firewall rules or services, does not mutate model or dataset files, and does not modify host or VM state.
- The `--require-pass` path exits non-zero when contract evidence is missing, malformed, privacy-scope mismatched, internally inconsistent, blocker-inconsistent, expected-artifact-empty, or marked pass while failed.

## Rollback

- Rollback is removal of the optional contract seal helper and its optional release-gate refresh wiring. Existing final-readiness manifest smoke JSON, Markdown, and `.summary.env` artifacts remain authoritative.
