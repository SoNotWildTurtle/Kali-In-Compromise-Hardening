# Changelog: NN IDS Release Schema Validation

## Added

- Added `tests/test_nn_ids_release_schema_contract_static.sh`, a dependency-free schema contract validation for `nn_ids_release_readiness_summary.py` artifacts.
- Added the schema contract test to the generated `evidence_manifest.static_validation_commands` list so reviewers see the validation path directly in machine-readable evidence.
- Updated NN IDS release readiness documentation with the focused schema contract validation command, safety boundary, compatibility impact, rollback notes, and follow-up work.

## Safety and compatibility

- The validation uses synthetic JSON fixtures only.
- It does not inspect live packets, datasets, models, raw telemetry, host state, VM state, hypervisor state, secrets, services, firewall policy, or network configuration.
- It does not start, stop, restart, retrain, restore, scan, block, install packages, contact external systems, or add persistence.
- Existing IDS audit, audit gate, retrain, restore, firstboot, packaging, host/VM controls, systemd units, and user workflows are unchanged.
- Rollback is a normal revert of the manifest command, schema contract test, documentation, and this changelog.

## Validation

Focused validation for this increment:

```bash
python3 -m py_compile nn_ids_release_readiness_summary.py
bash tests/test_nn_ids_release_readiness_summary_static.sh
bash tests/test_nn_ids_release_schema_contract_static.sh
bash tests/run_static_security_checks.sh
```

Hosted validation required before merge:

```text
Static Security Checks
```

## Follow-up

- Promote this dependency-free validator into a reusable schema-check helper if more artifact families need the same offline validation pattern.
- Wire IDS release readiness into the aggregate host/VM release posture once hosted workflows publish firstboot, restore, and IDS artifacts in a shared workspace.
- Add full JSON Schema validation when the repository adopts a pinned validator dependency.
