# NN IDS Alert Triage Playbook

## Added

- Added `docs/nn_ids_alert_triage_playbook.md`, a passive NN IDS alert triage playbook for release gates, firstboot handoffs, and recovery review that maps aggregate IDS evidence into conservative `pass`, `watch`, `degraded`, and `blocked` decisions with a stable triage record template.
- Added `tests/test_nn_ids_alert_triage_playbook_static.sh` to verify the playbook preserves passive safety boundaries, links the current NN IDS evidence family, keeps analytical estimates framed as uncertain, documents accessibility guidance, and provides rollback notes.

## Security

- The playbook is additive and documentation-only: it does not read packets, payloads, raw telemetry, secrets, live host state, VM state, or hypervisor state.
- The triage workflow explicitly keeps `human_review_required=true` and `live_action_authorized=false`, and it requires separate reviewed changes before any live-state remediation, restore, retrain, service, firewall, or hypervisor action.

## Validation

- Added focused validation command: `bash tests/test_nn_ids_alert_triage_playbook_static.sh`.
