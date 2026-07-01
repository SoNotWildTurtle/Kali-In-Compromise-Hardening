# NN IDS Release Readiness Summary

`nn_ids_release_readiness_summary.py` is a passive reviewer handoff tool for the neural-network IDS release chain. It consumes existing `nn_ids_model_audit.py` and `nn_ids_audit_gate.py` JSON artifacts, checks the minimum release contract, and writes a compact JSON and optional key/value report.

It does not read packets, datasets, models, raw telemetry, host or VM state. It does not start, stop, restart, install, remove, scan, block, restore, retrain, contact external systems, or add persistence. It is defensive evidence composition only.

## Usage

```bash
python3 nn_ids_release_readiness_summary.py \
  --model-audit /var/log/nn_ids_model_audit.json \
  --audit-gate /var/log/nn_ids_audit_gate.json \
  --output /var/log/nn_ids_release_readiness_summary.json \
  --report /var/log/nn_ids_release_readiness_summary.report \
  --strict
```

The command exits `0` when release readiness is satisfied. With `--strict`, it exits non-zero when the summary is blocked so hosted gates can fail closed.

## Decisions

- `ids_release_ready`: model audit and audit gate artifacts are present, well-formed, passive, and the gate decision is `accept` or `watch` with auto actions disabled.
- `ids_release_blocked`: an artifact is missing, malformed, has invalid metrics, requests live auto actions, or the audit gate decision is `retrain` or `restore`.

`watch` is allowed for release evidence because it is a non-mutating collect-more-evidence state. `retrain` and `restore` remain blocked because they require remediation before release promotion.

## Evidence manifest

Each generated artifact includes `evidence_manifest` so reviewers can identify the validation contract directly from the JSON:

- `schema_path=docs/schemas/nn_ids_release_readiness_summary.schema.json`
- `static_validation_commands` lists the focused local checks for this artifact.
- `hosted_required_checks` lists required hosted checks expected before merge.
- `safe_to_publish=true`, `contains_raw_telemetry=false`, and `contains_secrets=false` document the publication boundary.
- `live_state_validation_required=false` documents that this is aggregate evidence only.
- `human_review_required=true` preserves manual release-promotion review.

## JSON Schema contract

The schema requires the passive safety contract to remain explicit:

- `changes_live_state=false`
- `reads_raw_telemetry=false`
- `aggregate_evidence_only=true`
- `audit_gate.auto_actions=false`
- `evidence_manifest.safe_to_publish=true`
- `evidence_manifest.contains_raw_telemetry=false`
- `evidence_manifest.contains_secrets=false`
- `rollback.live_state_rollback_required=false`

It also ties `ids_release_ready` to an empty `blocking_issues` list while blocked artifacts must include at least one blocking issue.

## Dependency-free schema validation

`tests/test_nn_ids_release_schema_contract_static.sh` generates synthetic ready and blocked artifacts and validates the schema contract without installing `jsonschema` or any network dependency. The test checks required top-level fields, constants, enum values, bounded metrics, manifest commands, hosted check names, ready/blocking semantics, and fail-closed `retrain` behavior.

This complements the focused behavior test. It is intentionally static and synthetic: it does not inspect live IDS state, raw packets, datasets, models, host state, VM state, secrets, or telemetry.

## Validation

Focused validation:

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

## Compatibility

This is additive and backwards compatible. Existing IDS model audit, audit gate, retrain, restore, services, timers, firstboot, packaging, host/VM policy, firewall, telemetry, and user workflows are unchanged.

## Rollback

Rollback is a normal revert of the CLI manifest command, schema contract static test, documentation, and changelog. No host, VM, package, service, firewall, hypervisor, IDS dataset, model, secret, or telemetry state requires rollback.

## Follow-up

- Wire IDS release readiness into the aggregate host/VM release posture once firstboot and restore artifacts share a hosted workspace.
- Add hosted JSON Schema validation once the repository adopts a reusable validator.
- Extend IDS audit evidence with calibrated confidence intervals and dataset provenance hashes.
