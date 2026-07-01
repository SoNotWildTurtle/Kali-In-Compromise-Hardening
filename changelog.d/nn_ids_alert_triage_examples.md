# NN IDS Alert Triage Examples

## Added

- Added `docs/nn_ids_alert_triage_examples.md` with synthetic `pass`, `watch`, `degraded`, and `blocked` triage records for release receipts, firstboot handoffs, recovery bundles, and reviewer training.
- Added `tests/test_nn_ids_alert_triage_examples_static.sh` to verify the examples preserve stable `key=value` handoff fields, current NN IDS evidence references, accessibility guidance, rollback guidance, and passive safety boundaries.

## Security

- The examples are documentation-only and do not inspect live IDS, host, VM, or hypervisor state; this exact passive-boundary wording is covered by static validation.
- Records keep `human_review_required=true`, `live_action_authorized=false`, aggregate-only evidence, and uncertainty notes so examples cannot be mistaken for permission to remediate, restore, retrain, mutate firewall rules, mutate services, or change hypervisor state.

## Validation

- Added focused validation command: `bash tests/test_nn_ids_alert_triage_examples_static.sh`.
