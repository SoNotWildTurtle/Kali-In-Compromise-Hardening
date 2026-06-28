# Firstboot release-gate handoff summary smoke changelog

## 2026-06-28

- Added `firstboot_release_gate_handoff_summary_smoke.py`, a passive aggregate-only reader for `/var/log/firstboot_release_gate.handoff_freshness.summary.env`.
- Added JSON and Markdown smoke outputs for lightweight release, firstboot, and operator handoff checks.
- Added fail-closed validation for missing keys, malformed lines, invalid integers, privacy-scope mismatches, component mismatches, and contradictory `ok`/`decision`/`release_gate` states.
- Packaged the helper into custom ISO builds and wired it into `firstboot_release_gate.service` after handoff freshness summary generation.
- Added tests for passing summaries, contradictory summaries, missing required keys, Markdown output, packaging, service wiring, and documentation contracts.

## Security and privacy notes

- Read-only helper; no host, VM, firewall, service, network, model, dataset, restore, approval, or firstboot state is changed.
- Smoke evidence remains aggregate-only and excludes raw telemetry, logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, datasets, and environment identifiers.
- The authoritative freshness JSON/Markdown and upstream handoff artifacts remain unchanged.
