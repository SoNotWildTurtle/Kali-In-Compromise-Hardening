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

## Usage

Validate record shape and passive safety boundaries:

```bash
bash nn_ids_triage_record_validate.sh path/to/triage-record.env
```

Validate that the record is acceptable as release-gate evidence:

```bash
bash nn_ids_triage_record_validate.sh --release-gate path/to/triage-record.env
```

Release-gate mode accepts only `pass` and `watch` decisions with `release_ready=true`, no blocking issues, aggregate-only privacy scope, human review still required, and `live_action_authorized=false`. It rejects `degraded` and `blocked` records so they can be used as handoff evidence but not as promotion evidence.

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

## Compatibility impact

This is additive and backwards compatible. Existing NN IDS release readiness, model-card, drift, health, posture bundle, firstboot, restore, service, timer, schema, and host/VM policy workflows remain unchanged.

## Rollback

Rollback is a normal revert of the validator, this document, the changelog fragment, and static tests. No host, VM, service, firewall, IDS model, dataset, telemetry, secret, package, hypervisor, firstboot, restore, or runtime state requires rollback.

## Follow-up work

- Convert Markdown examples into fixture files once the repository standardizes triage-record artifact locations.
- Wire validator output into release receipts and posture bundle manifests.
- Add JSON-schema parity after the key/value record contract stabilizes.
