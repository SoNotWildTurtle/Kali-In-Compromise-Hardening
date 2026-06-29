# Changelog fragment: firstboot release receipt

## Added

- Added `firstboot_final_readiness_release_receipt.py`, a passive final receipt helper that consumes operator-bundle index JSON and emits approved/deferred JSON, Markdown, and `.summary.env` release evidence.
- Packaged the release receipt helper, wired `firstboot_release_gate.service` to refresh receipt artifacts after the operator-bundle index, and added static coverage for approved/deferred receipts, service wiring, packaging, documentation, rollback, and privacy boundaries.

## Security

- The release receipt helper is additive and passive: it reads only aggregate operator-bundle index evidence and does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, modify models or datasets, or alter host/VM state.
- The `--require-approved` path exits non-zero for missing, malformed, deferred, incomplete, missing-artifact, or zero-byte evidence so release gates can stop cleanly without attempting automatic repair.
