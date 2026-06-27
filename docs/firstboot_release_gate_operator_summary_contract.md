# Firstboot release gate operator summary contract

This note defines the additive interface for the passive firstboot release gate: a compact operator summary artifact generated beside the existing JSON and Markdown reports.

## Goal

The current release gate composes host/VM firstboot handoff evidence with NN IDS model-card evidence into privacy-safe JSON and Markdown artifacts. The operations workflow also needs a small shell-friendly status file that can be consumed by firstboot scripts, release gates, ISO packaging checks, dashboards, and recovery runbooks without parsing the full JSON report.

## Generated artifact

Default path:

```text
/var/log/firstboot_release_gate.summary.env
```

CLI usage:

```bash
python3 firstboot_release_gate.py \
  --firstboot-manifest /var/log/host_vm_policy_firstboot_manifest.json \
  --model-card /var/log/nn_ids_model_card.json \
  --output /var/log/firstboot_release_gate.json \
  --markdown /var/log/firstboot_release_gate.md \
  --summary /var/log/firstboot_release_gate.summary.env \
  --max-artifact-age-minutes 240
```

Passing an empty `--summary ''` value disables summary generation for deployments that do not want the extra artifact.

## Stable fields

The summary contains only quoted key/value pairs with stable names:

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

`FIRSTBOOT_RELEASE_GATE_STATUS` mirrors the existing JSON `release_gate` value (`pass` or `stop`). `FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT` counts stale, future-mtime, or unavailable-mtime freshness blockers only; other blocker categories remain represented by `FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT`.

## Contract requirements

- The summary is passive and generated from the already-built gate object.
- The summary does not execute host commands, change services, modify firewall state, update models, change datasets, approve restores, or alter firstboot state.
- The summary does not embed raw logs, packet contents, capture files, credentials, hostnames, usernames, secrets, model artifacts, datasets, or environment identifiers.
- Values are single-line, quoted, and safe for basic shell parsing.
- The existing JSON and Markdown outputs remain authoritative; the summary is a convenience layer for automation and dashboards.
- The default `firstboot_release_gate.service` writes JSON, Markdown, and summary artifacts to `/var/log` while preserving the existing read-only input boundary and systemd sandboxing.

## Validation checklist

- Static coverage proves that the CLI exposes `--summary`.
- Static coverage proves the default service writes the summary path.
- Static coverage proves generated fields include decision, release status, blocker count, artifact count, stale/skewed count, and privacy scope.
- Static coverage proves the summary excludes raw telemetry and identity-bearing data.
- Existing release-gate JSON and Markdown tests remain authoritative and continue to validate approved, deferred, missing-artifact, and invalid freshness-threshold behavior.

## Rollback

Rollback is additive and low risk:

1. Stop passing `--summary` in service or release-gate invocations, or pass `--summary ''` to disable generation.
2. Delete `/var/log/firstboot_release_gate.summary.env` if generated.
3. Revert the summary writer, service argument, tests, and this contract note.

The upstream host/VM firstboot manifest, NN IDS model card, JSON release gate, and Markdown release gate are not modified by this interface.

## Follow-up work

- Add a dashboard or smoke-check reader that consumes only `firstboot_release_gate.summary.env` for at-a-glance operator status.
- Consider adding release-bundle packaging that includes the JSON, Markdown, and summary artifacts together by SHA-256.
