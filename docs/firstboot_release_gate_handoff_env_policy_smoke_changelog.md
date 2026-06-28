# Firstboot release-gate handoff env-policy smoke changelog

## 2026-06-28

- Added optional `--summary` output to `firstboot_release_gate_handoff_env_policy_smoke.py`.
- Added shell-safe `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_` key/value evidence for aggregate release dashboards and chained posture readers.
- Wired firstboot refresh for `/var/log/firstboot_release_gate.handoff_env_policy_smoke.summary.env` alongside JSON and Markdown smoke artifacts.
- Documented the summary sidecar, privacy boundaries, rollback path, and compatibility notes.
- Added pytest coverage for approved summary sidecar output, fail-closed summary output, and static packaging/service/docs contracts.

## Security

- The helper remains read-only and aggregate-only.
- Summary output does not include raw logs, packet captures, private identifiers, credentials, telemetry payloads, model binaries, IDS datasets, or live host/VM state.
- The summary sidecar does not approve releases, override failed gates, alter host/VM controls, mutate IDS models, change firewall policy, modify restore approvals, or restart services.
- Service wiring is additive and keeps the existing systemd sandboxing posture.

## Rollback

- Stop passing `--summary` in local release or firstboot handoff workflows.
- Remove the optional `firstboot_release_gate.service` argument that writes `/var/log/firstboot_release_gate.handoff_env_policy_smoke.summary.env`.
- Delete optional generated env-policy smoke `.summary.env` files.
- Keep upstream env-policy JSON, Markdown, and smoke artifacts unchanged.
