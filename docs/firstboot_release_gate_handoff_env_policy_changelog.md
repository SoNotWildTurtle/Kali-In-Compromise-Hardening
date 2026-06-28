# Firstboot release-gate handoff env policy changelog

## 2026-06-28

- Added `firstboot_release_gate_handoff_env_policy.py` as an optional passive validator for status-reader `.summary.env` evidence.
- Added JSON, Markdown, and text rendering for aggregate env policy decisions.
- Added fail-closed checks for missing fields, invalid privacy scope, pass/fail mismatches, blocker-count mismatches, and zero reported artifacts.
- Added optional `--summary` output for shell-safe `FIRSTBOOT_HANDOFF_ENV_POLICY_` key/value sidecars.
- Wired firstboot refresh for `/var/log/firstboot_release_gate.handoff_env_policy.summary.env` alongside JSON and Markdown env-policy artifacts.
- Added pytest coverage for approved evidence, mismatched release-gate evidence, blocker-count mismatch behavior, Markdown privacy/rollback output, summary sidecar output, and packaging/service/docs contracts.

## Security

- The helper is read-only and aggregate-only.
- It does not change live system state, restart services, open network sockets, approve releases, alter host/VM controls, mutate IDS models, or modify firstboot evidence.
- It excludes raw telemetry, raw logs, packets, captures, private identifiers, model binaries, and datasets from rendered output.
- Summary sidecars expose compact policy state only and do not include raw logs, packet captures, model binaries, datasets, private identifiers, or telemetry payloads.
- Service wiring is additive and keeps the existing systemd sandboxing posture.

## Rollback

- Remove `firstboot_release_gate_handoff_env_policy.py` from local release or handoff workflows.
- Remove the helper from `build_custom_iso.sh` packaging if custom images should not include it.
- Remove the optional `firstboot_release_gate.service` `ExecStartPost=` lines that write env-policy JSON, Markdown, or summary env artifacts.
- Delete optional generated env-policy JSON, Markdown, or summary env files.
- Keep upstream firstboot release-gate and handoff artifacts unchanged.
