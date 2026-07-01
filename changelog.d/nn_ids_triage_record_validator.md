# NN IDS Triage Record Validator

## Added

- Added `nn_ids_triage_record_validate.sh`, a dependency-free passive validator for aggregate-only NN IDS triage records.
- Added `docs/nn_ids_triage_record_validator.md` with usage, safety boundary, compatibility, rollback, and follow-up notes.
- Added `tests/test_nn_ids_triage_record_validator_static.sh` to verify validator syntax, documentation coverage, changelog coverage, accepted handoff records, release-gate behavior, and fail-closed malformed or unsafe records.
- Added `--print-template` so reviewers can generate a conservative aggregate-only starter record that defaults to `triage_decision=watch`, `release_ready=false`, `human_review_required=true`, and `live_action_authorized=false`.

## Security

- The validator reads one local `key=value` record and does not inspect live IDS, host, VM, hypervisor, packet, payload, or telemetry state.
- The validator keeps `human_review_required=true`, requires `live_action_authorized=false`, rejects `live_action_authorized=true`, requires aggregate-only privacy wording, requires uncertainty notes, requires rollback references, and treats command-like operational text as unsafe.
- Release-gate mode accepts only `pass` and `watch` records with `release_ready=true` and no blocking issues; `degraded` and `blocked` records remain valid handoff evidence but cannot promote a release.
- `--print-template` prints text only, performs no live checks, and remains non-release-ready until a reviewer fills in evidence and reruns validation.

## Validation

- Added focused validation command: `bash tests/test_nn_ids_triage_record_validator_static.sh`.
- Repo-wide validation remains: `bash tests/run_static_security_checks.sh`.
