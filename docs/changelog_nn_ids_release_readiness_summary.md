# Changelog: NN IDS Release Readiness Summary

## Added

- Added `nn_ids_release_readiness_summary.py`, a passive release-readiness handoff CLI for NN IDS evidence.
- Added a JSON Schema documentation contract for the IDS release-readiness artifact.
- Added static tests with synthetic ready and blocked fixtures.
- Added documentation covering usage, decisions, safety boundaries, compatibility, rollback, validation, and follow-up work.

## Safety and compatibility

- This increment composes already-generated IDS model-audit and audit-gate JSON artifacts only.
- It does not read packets, datasets, models, raw telemetry, host or VM state.
- It does not start, stop, restart, retrain, restore, scan, block IPs, install packages, change firewall rules, contact external systems, or add persistence.
- Existing IDS audit, audit gate, retrain, restore, service, timer, firstboot, packaging, host/VM policy, and user workflows remain unchanged.
- Rollback is a normal revert of the CLI, schema, tests, docs, README entry, and this changelog.

## Validation

Focused validation for this increment:

```bash
python3 -m py_compile nn_ids_release_readiness_summary.py
bash tests/test_nn_ids_release_readiness_summary_static.sh
bash tests/run_static_security_checks.sh
```

Hosted validation required before merge:

```text
Static Security Checks
```

## Follow-up

- Wire IDS release readiness into the aggregate host/VM release posture once hosted workflows publish firstboot, restore, and IDS artifacts in a shared workspace.
- Add hosted JSON Schema validation once the repository adopts a reusable validator.
- Extend IDS audit evidence with calibrated confidence intervals and dataset provenance hashes.
