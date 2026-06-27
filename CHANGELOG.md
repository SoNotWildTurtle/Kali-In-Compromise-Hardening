# Changelog

## Unreleased

### Added

- Added `firstboot_release_gate_bundle_manifest.py`, a passive privacy-safe bundle manifest that records JSON, Markdown, summary, and status artifact presence, sizes, and SHA-256 hashes for release handoff without embedding raw telemetry.
- Added `docs/firstboot_release_gate_bundle_manifest.md`, ISO packaging coverage, and tests for passing manifests, missing artifact blockers, nonpassing status blockers, privacy boundaries, and `--require-pass` behavior.
- Added `firstboot_release_gate_status.py`, a passive aggregate-only reader for `firstboot_release_gate.summary.env` that emits text or JSON status for dashboards, smoke checks, shift handoffs, and release gates without sourcing shell content.
- Added `docs/firstboot_release_gate_status.md`, packaging coverage, and tests for passing summaries, deferred status, malformed summary validation, privacy-scope enforcement, and text output.

### Security

- The firstboot release-gate bundle manifest is passive and privacy-safe: it records only artifact paths, presence, sizes, SHA-256 hashes, and aggregate status-reader fields.
- The bundle manifest `--require-pass` path exits non-zero when release-gate evidence is missing, malformed, nonpassing, or validation-blocked, giving ISO promotion and recovery handoff workflows an auditable stop condition without changing services, timers, firewall rules, model artifacts, datasets, host settings, VM settings, approvals, or restore state.
