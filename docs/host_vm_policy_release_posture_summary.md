# Host/VM Policy Aggregate Release Posture Summary

`host_vm_policy_release_posture_summary.py` creates a passive release posture artifact from already-summarized firstboot and restore evidence.

The CLI is intended for reviewer handoff and release-gate composition. It does not execute firstboot, execute restore actions, inspect live host or VM state, read raw telemetry, load IDS datasets or models, install packages, change firewall rules, reload services, contact external systems, or add persistence.

## Inputs

The summary expects two aggregate JSON artifacts:

- `--firstboot-summary`: output from `host_vm_policy_firstboot_release_summary.py` with `decision=summary_ready` and `summary_ready=true`.
- `--restore-summary`: output from `host_vm_policy_restore_release_summary.py` with `decision=restore_summary_ready` and `summary_ready=true`.

Both inputs must declare:

- `changes_live_state=false`
- `reads_raw_telemetry=false`
- `aggregate_evidence_only=true`
- `blocking_issues` as a JSON list

Restore evidence must also declare `requires_manual_invocation=true` so the manual restore boundary remains explicit.

## Usage

```bash
python3 host_vm_policy_release_posture_summary.py \
  --firstboot-summary firstboot-release-summary.json \
  --restore-summary restore-release-summary.json \
  --output release-posture-summary.json \
  --report release-posture-summary.report \
  --strict
```

`--strict` exits non-zero unless the combined posture is ready. This lets hosted release gates fail closed without re-running live firstboot or restore operations.

## Output decisions

- `release_posture_ready`: firstboot and restore summaries are both ready, aggregate-only, non-mutating, and free of blocking issues.
- `release_posture_blocked`: at least one required summary is missing, malformed, unsafe, blocked, or not ready.

The JSON output contains component decisions, blocking issue counts, passive safety fields, reviewer handoff details, evidence manifest, rollback notes, and follow-up work. The compact report mirrors the same posture decision and publishability fields in key/value form for shell-based gates.

## Evidence manifest

Each generated posture artifact now includes `evidence_manifest` so a reviewer or hosted gate can identify the validation contract without reading project docs by hand:

- `schema_path=docs/schemas/host_vm_policy_release_posture_summary.schema.json`
- `static_validation_commands` lists the focused local checks for this artifact family.
- `hosted_required_checks` lists the required hosted release gates expected before merge.
- `safe_to_publish=true`, `contains_raw_telemetry=false`, and `contains_secrets=false` make the publication boundary explicit.
- `live_state_validation_required=false` documents that this artifact is derived from aggregate summaries only.
- `human_review_required=true` preserves the manual release-promotion boundary.

These fields are informational and defensive. They do not trigger automated release promotion, execute restore, collect telemetry, or inspect live systems.

## JSON Schema contract

The posture artifact schema lives at:

```text
docs/schemas/host_vm_policy_release_posture_summary.schema.json
```

The schema requires the passive safety contract to remain explicit:

- `changes_live_state=false`
- `reads_raw_telemetry=false`
- `aggregate_evidence_only=true`
- `reviewer_handoff.requires_human_review_before_release_promotion=true`
- `evidence_manifest.safe_to_publish=true`
- `evidence_manifest.contains_raw_telemetry=false`
- `evidence_manifest.contains_secrets=false`
- `rollback.live_state_rollback_required=false`

It also ties `release_posture_ready` to `posture_ready=true` and an empty `blocking_issues` list, while `release_posture_blocked` must carry at least one blocking issue. The schema is intentionally stored as documentation rather than as a runtime dependency so release gates can validate examples without requiring third-party Python packages.

## Threat-model rationale

This layer reduces reviewer error by producing one machine-readable posture decision from two independent release summaries. It intentionally consumes only aggregate summaries rather than raw firstboot logs, restore executor output, telemetry, IDS data, or system state. That keeps the posture gate auditable, reproducible, and safe to publish as release evidence.

The posture summary does not replace module-specific validation. It composes existing firstboot and restore release evidence so later workflows can promote a coherent product state only after both subsystems are ready.

## Compatibility

This is additive and backwards compatible. Existing firstboot, restore, packaging, services, systemd units, smoke checks, IDS behavior, and user workflows are unchanged. The new `evidence_manifest` field extends the JSON artifact while preserving existing top-level readiness, component, blocking issue, and report fields.

## Validation

Focused validation:

```bash
bash tests/test_host_vm_policy_release_posture_summary_static.sh
bash tests/test_host_vm_policy_release_posture_summary_schema_static.sh
bash tests/run_static_security_checks.sh
```

Hosted validation required before merge:

```text
Static Security Checks
Restore Executor Release Gate
```

## Rollback

Revert `host_vm_policy_release_posture_summary.py`, `tests/test_host_vm_policy_release_posture_summary_static.sh`, `tests/test_host_vm_policy_release_posture_summary_schema_static.sh`, `docs/schemas/host_vm_policy_release_posture_summary.schema.json`, this document, and the changelog entry. No host, VM, package, service, firewall, hypervisor, IDS, dataset, model, or telemetry state requires rollback.

## Known limitations

- This does not yet consume IDS aggregate evidence because IDS readiness artifacts do not use the same ready/blocked release-summary semantics.
- This is not yet wired into a hosted aggregate release gate; it is a local/reviewer CLI plus static/schema coverage.
- The schema test is dependency-free and intentionally checks the repository contract fields rather than implementing a full JSON Schema engine.

## Follow-up work

- Add an IDS aggregate release summary with matching passive ready/blocked semantics.
- Add hosted schema validation once the repository adopts a JSON Schema validation dependency or reusable validator.
- Wire firstboot, restore, and IDS aggregate evidence into one hosted release posture workflow.
