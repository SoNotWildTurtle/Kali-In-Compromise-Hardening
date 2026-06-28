# Changelog fragment: firstboot release-gate handoff env-policy smoke

## Added

- Added `firstboot_release_gate_handoff_env_policy_smoke.py`, a passive aggregate-only smoke validator for the env-policy `.summary.env` sidecar.
- Added JSON and Markdown smoke artifacts for lightweight release dashboards and operator handoffs.
- Packaged the helper into custom ISO builds and wired `firstboot_release_gate.service` to refresh smoke artifacts after env-policy evidence is generated.
- Added static behavior coverage for approved evidence, privacy-scope mismatch blockers, missing required keys, documentation coverage, firstboot service wiring, and ISO packaging.

## Security

- The smoke helper is additive and read-only: it parses existing aggregate summary evidence, emits derived evidence, and does not mutate live host, VM, firewall, service, IDS, approval, restore, package, or firstboot state.
- The `--require-pass` path exits non-zero when env-policy summary evidence is missing, malformed, internally inconsistent, privacy-scope mismatched, or reports no handoff artifacts.
- The helper is aggregate-only and does not consume raw telemetry, packet captures, credentials, private identifiers, model binaries, or IDS datasets.

## Rollback

- Remove the optional helper from `build_custom_iso.sh` packaging and remove the two `firstboot_release_gate.service` `ExecStartPost=` lines that emit env-policy smoke JSON and Markdown artifacts.
- Delete optional generated `/var/log/firstboot_release_gate.handoff_env_policy_smoke.*` artifacts.
- Keep upstream release-gate, status-reader, and env-policy JSON/Markdown artifacts unchanged.
