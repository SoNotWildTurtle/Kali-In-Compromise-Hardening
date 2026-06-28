# Changelog: firstboot final readiness helper

## Added

- Added `firstboot_final_readiness.py` as a passive aggregate-only final readiness helper.
- Added JSON, Markdown, and `.summary.env` output support for release-gate handoff evidence.
- Added firstboot service refresh coverage after the env-policy smoke gate.
- Added static tests for approved, malformed, privacy-mismatched, and deferred evidence.

## Security and privacy

- The helper reads only aggregate shell-safe summary evidence.
- It does not read raw packets, credentials, private logs, datasets, model binaries, or live host/VM state.
- It fails closed to `deferred` and `stop` when evidence is missing, malformed, privacy-mismatched, or inconsistent.

## Compatibility

- Additive helper only; no existing CLI, service, timer, restore, IDS, policy, or host-hardening behavior is removed.

## Rollback

- Remove `firstboot_final_readiness.py` from packaging and remove the final readiness `ExecStartPost` lines from `firstboot_release_gate.service`.
- Existing env-policy smoke evidence remains authoritative.
