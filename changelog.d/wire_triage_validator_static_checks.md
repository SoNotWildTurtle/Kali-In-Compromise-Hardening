# Wire Triage Validator Static Checks

## Changed

- Added the passive NN IDS triage record validator, its documentation, changelog fragment, and focused static test to the repo-wide critical guardrail presence checks.
- Preserved the validator as a local evidence check only; it remains separate from firstboot, service, timer, host, VM, hypervisor, packet, payload, and telemetry inspection paths.

## Validation

- Repo-wide validation target: `bash tests/run_static_security_checks.sh`.
- Focused validator target remains: `bash tests/test_nn_ids_triage_record_validator_static.sh`.

## Rollback

- Roll back by reverting the static-check list update and this changelog fragment. No runtime, firewall, IDS model, telemetry, dataset, service, timer, restore, firstboot, or package state is changed.
