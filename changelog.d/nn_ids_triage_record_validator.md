# NN IDS Triage Record Validator

## Added

- Added `nn_ids_triage_record_validate.sh`, a dependency-free passive validator for aggregate-only NN IDS triage records.
- Added `docs/nn_ids_triage_record_validator.md` with usage, safety boundary, compatibility, rollback, and follow-up notes.
- Added `tests/test_nn_ids_triage_record_validator_static.sh` to verify validator syntax, documentation coverage, changelog coverage, accepted handoff records, release-gate behavior, and fail-closed malformed or unsafe records.
- Added `--print-template` so reviewers can generate a conservative aggregate-only starter record that defaults to `triage_decision=watch`, `release_ready=false`, `human_review_required=true`, and `live_action_authorized=false`.
- Added fixture records in `examples/nn_ids_triage_records/pass_release_ready.env` and `examples/nn_ids_triage_records/watch_handoff.env`, plus `tests/test_nn_ids_triage_fixtures_static.sh`, so reviewer handoffs and release notes can reuse validated passive examples.
- Added degraded and blocked fixture records in `examples/nn_ids_triage_records/degraded_handoff.env` and `examples/nn_ids_triage_records/blocked_handoff.env` so stale, incomplete, or missing aggregate evidence has explicit passive handoff examples.
- Added `schemas/nn_ids_triage_record.schema.json`, a machine-readable JSON schema for passive NN IDS triage records and release handoff bundles.
- Added `tests/test_nn_ids_triage_record_schema_static.sh` to verify schema JSON parsing, required-key parity with the shell validator, fixture parity, `release_gate_contract` coverage, and conservative safety tokens.
- Added `--emit-json` so validated key/value triage records can be exported as schema-compatible JSON for release receipts, posture bundle manifests, and reviewer handoff tooling.
- Added `nn_ids_triage_bundle_manifest.py` plus `tests/test_nn_ids_triage_bundle_manifest_static.sh` so validated JSON triage records can be gathered into a passive aggregate-only bundle manifest with record hashes, decision counts, blocker counts, owner handoff, and follow-up evidence.

## Security

- The validator reads one local `key=value` record and does not inspect live IDS, host, VM, hypervisor, packet, payload, or telemetry state.
- The validator keeps `human_review_required=true`, requires `live_action_authorized=false`, rejects `live_action_authorized=true`, requires aggregate-only privacy wording, requires uncertainty notes, requires rollback references, and treats command-like operational text as unsafe.
- Release-gate mode accepts only `pass` and `watch` records with `release_ready=true` and no blocking issues; `degraded` and `blocked` records remain valid handoff evidence but cannot promote a release.
- `--print-template` prints text only, performs no live checks, and remains non-release-ready until a reviewer fills in evidence and reruns validation.
- Fixture examples are static local text records only; they contain no raw telemetry, secrets, host identifiers, VM identifiers, packet captures, payloads, or operational commands.
- The degraded and blocked fixtures intentionally fail release-gate mode while passing normal passive validation, preserving conservative reviewer handoff without authorizing promotion.
- The JSON schema is static documentation and validation evidence only. It adds no runtime mutation, no credential access, no live-state inspection, and no authority to execute IDS, host, VM, hypervisor, firewall, restore, retraining, or response actions.
- `--emit-json` runs after the same fail-closed validation path, emits only the stable schema keys, keeps booleans typed, and does not add live-state authority, raw telemetry, secrets, host identifiers, VM identifiers, packet captures, payloads, or operational commands.
- The triage bundle manifest helper reads local JSON records only, rejects unexpected keys and live-action authorization, hashes source records, summarizes aggregate evidence, and does not inspect live IDS, host, VM, hypervisor, packet, payload, firewall, restore, retraining, service, network, or telemetry state.

## Validation

- Added focused validation command: `bash tests/test_nn_ids_triage_record_validator_static.sh`.
- Added fixture validation command: `bash tests/test_nn_ids_triage_fixtures_static.sh`.
- Added schema validation command: `bash tests/test_nn_ids_triage_record_schema_static.sh`.
- JSON export behavior is covered by `bash tests/test_nn_ids_triage_record_validator_static.sh`.
- Triage bundle manifest behavior is covered by `bash tests/test_nn_ids_triage_bundle_manifest_static.sh`.
- Repo-wide validation remains: `bash tests/run_static_security_checks.sh`.
