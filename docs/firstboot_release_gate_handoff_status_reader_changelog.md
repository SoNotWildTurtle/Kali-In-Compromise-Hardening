# Changelog fragment: firstboot release-gate handoff status reader

## Added

- Added `firstboot_release_gate_handoff_status_reader.py`, a passive aggregate-only terminal reader that summarizes firstboot handoff smoke JSON as compact text, JSON, or Markdown.
- Added fail-closed validation for missing smoke evidence, invalid JSON, component mismatches, privacy-scope mismatches, contradictory `ok`/`decision`/`release_gate` values, and passing source evidence that still carries blockers.
- Added tests for passing text output, deferred JSON output, contradictory source values, Markdown privacy/rollback content, Python compile coverage, documentation coverage, changelog coverage, and ISO packaging coverage.
- Packaged the reader in `build_custom_iso.sh` so custom Kali images include the optional operator status helper by default.
- Added `firstboot_release_gate.service` refresh wiring for `/var/log/firstboot_release_gate.handoff_status_reader.json` and `/var/log/firstboot_release_gate.handoff_status_reader.md` so firstboot handoffs include compact status-reader artifacts by default.
- Added static service-contract assertions for the generated JSON and Markdown status-reader artifacts.

## Security

- The helper is read-only and aggregate-only. It does not change live system state, approve releases, restart services, open sockets, alter host/VM controls, or modify firstboot evidence.
- The `--require-pass` path exits non-zero unless compact status evidence is approved and internally consistent.
- The helper excludes raw telemetry, raw logs, packets, captures, private identifiers, model binaries, and datasets from rendered output.
- The service wiring is additive and keeps existing systemd sandboxing, capability bounding, read-only input paths, and `/var/log`-scoped write behavior.

## Rollback

- Remove `firstboot_release_gate_handoff_status_reader.py` from local release or handoff workflows.
- Remove the helper from `build_custom_iso.sh` packaging if custom images should not include it.
- Remove the optional `firstboot_release_gate.service` `ExecStartPost=` lines that write handoff-status-reader JSON and Markdown artifacts.
- Delete optional generated handoff-status-reader JSON or Markdown files.
- Keep authoritative smoke, freshness, verification, index, digest, bundle, and release-gate artifacts unchanged.
