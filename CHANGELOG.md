# Changelog

## Unreleased

### Added

- Added `nn_ids_health_evidence.py`, a passive JSON evidence emitter for NN IDS model freshness, latest training metrics, service-health log markers, and readable capture/dataset inputs.
- Added static and behavior-oriented coverage in `tests/test_nn_ids_health_evidence_static.sh` for passing posture, low metric failures, restart warnings, and missing model failures.
- Added `docs/NN_IDS_HEALTH_EVIDENCE.md` with usage, schema, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.

### Security

- The NN IDS evidence emitter is read-only: it does not open network sockets, execute commands, restart services, change firewall rules, or modify host/VM state.
- `--require-pass` exits non-zero when model evidence, metric evidence, or recent health markers indicate degraded IDS posture.
