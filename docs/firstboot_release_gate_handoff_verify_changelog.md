# Firstboot release-gate handoff verification

## Added

- Added `firstboot_release_gate_handoff_verify.py`, a passive aggregate-only helper that verifies firstboot release-gate handoff indexes and recomputes SHA-256 hashes for copied handoff artifacts before ISO promotion, recovery review, or manager handoff.
- Added tests for matching hashes, fail-closed hash mismatches, Markdown handoff evidence, documentation, privacy exclusions, and rollback guidance.
- Added `docs/firstboot_release_gate_handoff_verify.md` with usage, output contract, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.

## Security

- The verifier is additive and passive: it reads only an existing handoff index and privacy-safe aggregate handoff artifacts, recomputes file sizes and SHA-256 hashes, and emits derived JSON or Markdown verification evidence.
- The `--require-verified` path exits non-zero when the index is missing, malformed, deferred, privacy-scope mismatched, or when indexed artifacts are missing, size-mismatched, hash-mismatched, or missing expected hashes.
- The verifier intentionally avoids raw telemetry, private identifiers, model payloads, datasets, live service changes, network changes, approval changes, recovery changes, and firstboot state changes.
