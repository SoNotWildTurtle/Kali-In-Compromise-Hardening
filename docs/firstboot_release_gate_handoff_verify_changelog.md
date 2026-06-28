# Firstboot release-gate handoff verification

## Added

- Added `firstboot_release_gate_handoff_verify.py`, a passive aggregate-only helper that verifies firstboot release-gate handoff indexes and recomputes SHA-256 hashes for copied handoff artifacts before ISO promotion, recovery review, or manager handoff.
- Packaged `firstboot_release_gate_handoff_verify.py` in `build_custom_iso.sh` so custom Kali images include the verifier by default.
- Wired `firstboot_release_gate.service` to refresh `/var/log/firstboot_release_gate.handoff_verify.json` and `/var/log/firstboot_release_gate.handoff_verify.md` after handoff index generation.
- Added tests for matching hashes, fail-closed hash mismatches, Markdown handoff evidence, packaging, service integration, documentation, privacy exclusions, and rollback guidance.
- Added `docs/firstboot_release_gate_handoff_verify.md` with usage, output contract, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.

## Security

- The verifier is additive and passive: it reads only an existing handoff index and privacy-safe aggregate handoff artifacts, recomputes file sizes and SHA-256 hashes, and emits derived JSON or Markdown verification evidence.
- The `--require-verified` path exits non-zero when the index is missing, malformed, deferred, privacy-scope mismatched, or when indexed artifacts are missing, size-mismatched, hash-mismatched, or missing expected hashes.
- The service integration writes derived handoff verification artifacts only, preserves the existing sandbox posture, requests no capabilities, and does not change live host, VM, firewall, service, IDS, approval, recovery, or firstboot state.
- The verifier intentionally avoids raw telemetry, private identifiers, model payloads, datasets, live service changes, network changes, approval changes, recovery changes, and firstboot state changes.
