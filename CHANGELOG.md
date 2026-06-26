# Changelog

## Unreleased

### Added

- Added `nn_ids_health_evidence.py`, a passive JSON evidence emitter for NN IDS model freshness, latest training metrics, service-health log markers, and readable capture/dataset inputs.
- Added `nn_ids_health_evidence.service` and `nn_ids_health_evidence.timer` to publish passive IDS posture evidence to `/var/log/nn_ids_health_evidence.json` on a recurring schedule.
- Packaged the NN IDS health evidence emitter, service, and timer in `build_custom_iso.sh` and wired firstboot to enable the timer plus write an immediate firstboot evidence artifact.
- Added static and behavior-oriented coverage in `tests/test_nn_ids_health_evidence_static.sh` for packaging, systemd hardening, passing posture, low metric failures, restart warnings, and missing model failures.
- Added `docs/NN_IDS_HEALTH_EVIDENCE.md` with usage, deployment integration, schema, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.

### Security

- The NN IDS evidence emitter is read-only: it does not open network sockets, execute commands, restart services, change firewall rules, or modify host/VM state.
- `nn_ids_health_evidence.service` uses systemd hardening controls including `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`, an empty capability bounding set, `ReadOnlyPaths=/opt/nnids`, and `ReadWritePaths=/var/log`.
- `--require-pass` exits non-zero when model evidence, metric evidence, or recent health markers indicate degraded IDS posture.
