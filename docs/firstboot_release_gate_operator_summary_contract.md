# Firstboot release gate operator summary contract

This note defines the next additive interface for the passive firstboot release gate: a compact operator summary artifact that can be generated beside the existing JSON and Markdown reports.

## Goal

The current release gate already composes host/VM firstboot handoff evidence with NN IDS model-card evidence into privacy-safe JSON and Markdown artifacts. The missing operations workflow is a small shell-friendly status file that can be consumed by firstboot scripts, release gates, ISO packaging checks, dashboards, and recovery runbooks without parsing the full JSON report.

## Proposed artifact

Default path:

```text
/var/log/firstboot_release_gate.summary.env
```

Recommended CLI flag:

```bash
python3 firstboot_release_gate.py \
  --firstboot-manifest /var/log/host_vm_policy_firstboot_manifest.json \
  --model-card /var/log/nn_ids_model_card.json \
  --output /var/log/firstboot_release_gate.json \
  --markdown /var/log/firstboot_release_gate.md \
  --summary /var/log/firstboot_release_gate.summary.env \
  --max-artifact-age-minutes 240
```

## Stable fields

The summary should contain only quoted key/value pairs with stable names:

```text
FIRSTBOOT_RELEASE_GATE_SCHEMA_VERSION="1"
FIRSTBOOT_RELEASE_GATE_COMPONENT="firstboot_release_gate"
FIRSTBOOT_RELEASE_GATE_CREATED_UTC="2026-06-27T15:00:00Z"
FIRSTBOOT_RELEASE_GATE_OK="true"
FIRSTBOOT_RELEASE_GATE_DECISION="approved"
FIRSTBOOT_RELEASE_GATE_STATUS="pass"
FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT="0"
FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT="2"
FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT="0"
FIRSTBOOT_RELEASE_GATE_PRIVACY_SCOPE="aggregate_only"
```

## Contract requirements

- The summary must be passive and generated from the already-built gate object.
- The summary must not execute host commands, change services, modify firewall state, update models, change datasets, approve restores, or alter firstboot state.
- The summary must not embed raw logs, packet contents, capture files, credentials, hostnames, usernames, secrets, model artifacts, datasets, or environment identifiers.
- Values must be single-line, quoted, and safe for basic shell parsing.
- The existing JSON and Markdown outputs remain authoritative; the summary is a convenience layer for automation and dashboards.
- Passing an empty `--summary ''` value should disable summary generation for deployments that do not want the extra artifact.

## Validation checklist

- Unit or static coverage proves that the CLI exposes `--summary`.
- Coverage proves the default service writes the summary path.
- Coverage proves generated fields include decision, release status, blocker count, artifact count, and privacy scope.
- Coverage proves privacy text excludes raw telemetry and identity-bearing data.
- Existing release-gate JSON and Markdown tests remain unchanged except where they assert the new additive default path.

## Rollback

Rollback is additive and low risk:

1. Stop passing `--summary` in service or release-gate invocations.
2. Delete `/var/log/firstboot_release_gate.summary.env` if generated.
3. Revert the summary writer, service argument, tests, and this contract note.

The upstream host/VM firstboot manifest, NN IDS model card, JSON release gate, and Markdown release gate are not modified by this interface.

## Follow-up implementation task

Implement the summary writer in `firstboot_release_gate.py`, wire the service to emit the default summary path, and add regression tests for the CLI flag, privacy boundary, service argument, and generated field contract.
