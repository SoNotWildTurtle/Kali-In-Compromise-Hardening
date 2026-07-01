# NN IDS Triage Record Validator

`nn_ids_triage_record_validate.sh` validates passive, aggregate-only NN IDS triage records before they are attached to release receipts, firstboot handoffs, recovery bundles, or reviewer notes.

The validator is dependency-free and shell-only so it can run in early release gates, minimal rescue shells, and review environments that should not install extra packages. It reads one local text file and does not inspect live IDS, host, VM, hypervisor, packet, payload, or telemetry state.

## Supported record shape

Records use the stable `key=value` template from `docs/nn_ids_alert_triage_playbook.md`:

```text
triage_decision=<pass|watch|degraded|blocked>
release_ready=<true|false>
source_artifacts=<comma-separated aggregate artifacts>
artifact_hashes=<sha256 entries or manifest reference>
blocking_issues=<none or concise blocker summary>
uncertainty_note=<why this remains an estimate>
privacy_scope=<aggregate-only; no raw telemetry or secrets>
human_review_required=true
live_action_authorized=false
rollback_reference=<docs/runbook or PR rollback notes>
next_evidence_needed=<freshness recheck, model card, drift review, or hosted gate>
owner=<review role or team>
```

## Machine-readable schema

`schemas/nn_ids_triage_record.schema.json` mirrors the shell validator contract as a dependency-free JSON schema artifact for release bundles, handoff manifests, and external reviewers that need a stable machine-readable contract.

The schema intentionally preserves the same conservative boundaries as the shell validator:

- `triage_decision` is limited to `pass`, `watch`, `degraded`, or `blocked`.
- `human_review_required` is always `true`.
- `live_action_authorized` is always `false`.
- `privacy_scope` must include `aggregate-only; no raw telemetry or secrets`.
- additional properties are rejected so raw telemetry, packet captures, payloads, secrets, host identifiers, and VM identifiers cannot be smuggled into a triage handoff.
- `release_gate_contract` documents that only release-ready `pass` or `watch` records with no blockers can promote a release; `degraded` and `blocked` remain valid handoff evidence only.

Validate schema parity with the shell validator and fixtures:

```bash
bash tests/test_nn_ids_triage_record_schema_static.sh
```

## Usage

Validate record shape and passive safety boundaries:

```bash
bash nn_ids_triage_record_validate.sh path/to/triage-record.env
```

Print a conservative passive starter record for reviewers:

```bash
bash nn_ids_triage_record_validate.sh --print-template > triage-record.env
```

The printed template defaults to `triage_decision=watch` and `release_ready=false` so it is valid handoff evidence but cannot pass release-gate mode until a reviewer replaces placeholders, confirms aggregate evidence freshness, and intentionally marks the record release-ready.

Validate that the record is acceptable as release-gate evidence:

```bash
bash nn_ids_triage_record_validate.sh --release-gate path/to/triage-record.env
```

Release-gate mode accepts only `pass` and `watch` decisions with `release_ready=true`, no blocking issues, aggregate-only privacy scope, human review still required, and `live_action_authorized=false`. It rejects `degraded` and `blocked` records so they can be used as handoff evidence but not as promotion evidence.

Export a validated record as schema-compatible JSON for release receipts, posture bundle manifests, or reviewer handoff tooling:

```bash
bash nn_ids_triage_record_validate.sh --emit-json path/to/triage-record.env > triage-record.json
```

`--emit-json` always runs the same validation before printing JSON. It emits only the stable schema keys, keeps booleans typed as JSON booleans, and does not add live-state metadata. It can be combined with `--release-gate` when reviewers need JSON evidence that has already passed release-gate checks:

```bash
bash nn_ids_triage_record_validate.sh --release-gate --emit-json path/to/triage-record.env > triage-record.release-gate.json
```

If validation fails, `--emit-json` prints no JSON and exits non-zero; it must not be used to bypass degraded, blocked, malformed, or unsafe records.

## Fixture examples

Reusable fixture records live under `examples/nn_ids_triage_records/` so reviewers and tests can share the same conservative record shapes:

- `examples/nn_ids_triage_records/pass_release_ready.env` demonstrates a release-ready aggregate record that passes normal validation and release-gate mode.
- `examples/nn_ids_triage_records/watch_handoff.env` demonstrates a conservative handoff record that passes normal validation but intentionally fails release-gate mode until a reviewer marks it release-ready.
- `examples/nn_ids_triage_records/degraded_handoff.env` demonstrates stale or incomplete aggregate evidence that is valid passive handoff evidence but is not release-ready.
- `examples/nn_ids_triage_records/blocked_handoff.env` demonstrates missing required aggregate release evidence that must remain blocked until reviewers provide replacement artifacts.

Validate the fixtures before copying them into release notes or handoff bundles:

```bash
bash tests/test_nn_ids_triage_fixtures_static.sh
```

## Safety checks

The validator fails closed when a record:

- omits or duplicates a required key;
- uses an unsupported decision value;
- weakens the human-review or live-action boundary;
- lacks aggregate-only privacy wording;
- lacks uncertainty or estimate language;
- lacks rollback guidance;
- lacks NN IDS aggregate evidence references;
- lacks a manifest or SHA-256 artifact hash reference;
- includes command-like operational text;
- includes private-key or access-token patterns;
- mentions raw telemetry, payloads, packet captures, secrets, or host/VM identifiers.

## Threat-model rationale

Triage records are evidence, not authority. They help reviewers make conservative decisions while keeping live-state changes in separate reviewed workflows. The validator enforces that boundary by requiring human review, rejecting live authorization, and treating operational command text as unsafe.

`--print-template` improves usability without increasing authority: it only prints local text, keeps the default record non-release-ready, and preserves the same passive aggregate-only constraints validated by normal mode.

Fixture examples improve reproducibility without increasing authority: they are static local text records, contain no secrets or raw telemetry, and are validated by the same passive script before they are used as review evidence. Degraded and blocked fixtures make failure-mode handoff records explicit while preserving fail-closed release-gate behavior.

The JSON schema improves handoff automation without increasing authority: it is a static machine-readable contract for aggregate review records, contains no runtime hooks, and is checked against the shell validator plus fixtures by `tests/test_nn_ids_triage_record_schema_static.sh`.

`--emit-json` improves handoff ergonomics without increasing authority: it reads the same local record, preserves the same fail-closed checks, emits schema-compatible evidence only after validation succeeds, and does not inspect live IDS, host, VM, hypervisor, packet, payload, firewall, restore, retraining, or telemetry state.

## Compatibility impact

This is additive and backwards compatible. Existing key/value validation, release-gate behavior, fixture records, NN IDS release readiness, model-card, drift, health, posture bundle, firstboot, restore, service, timer, schema, and host/VM policy workflows remain unchanged.

## Rollback

Rollback is a normal revert of the validator JSON export path, schema, this document, the changelog fragment, static tests, and fixture examples. No host, VM, service, firewall, IDS model, dataset, telemetry, secret, package, hypervisor, firstboot, restore, or runtime state requires rollback.

## Follow-up work

- Wire accepted JSON triage records into release receipts and posture bundle manifests.
- Add machine-readable examples for external release handoff bundles once manifest embedding is standardized.
- Add optional schema validation for emitted JSON in environments where a JSON Schema validator is already available.
