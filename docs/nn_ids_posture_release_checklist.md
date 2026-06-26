# NN IDS posture release checklist

`nn_ids_posture_release_checklist.py` turns the aggregate posture bundle manifest from `nn_ids_posture_bundle_manifest.py` into an actionable release, firstboot, or recovery checklist. It is designed for defensive operator handoff and release-gate review.

## Why this exists

The posture bundle manifest is machine-readable and privacy-safe. This checklist keeps that contract while adding explicit human actions:

- confirm the aggregate release gate is passing;
- confirm every required evidence artifact is present;
- confirm freshness policy failures are visible before promotion;
- preserve advisory warnings without blocking safe emergency recovery;
- give operators a concrete regeneration action for failed evidence.

The tool does not inspect network traffic or host state. It only reads the aggregate manifest fields already produced by the posture bundle flow.

## Usage

Generate the standard Markdown checklist:

```bash
python3 nn_ids_posture_release_checklist.py \
  --manifest /var/log/nn_ids_posture_bundle_manifest.json \
  --output /var/log/nn_ids_posture_release_checklist.md
```

Fail a release gate when required checklist items do not pass:

```bash
python3 nn_ids_posture_release_checklist.py \
  --manifest /var/log/nn_ids_posture_bundle_manifest.json \
  --require-pass
```

Generate machine-readable JSON for dashboards or CI:

```bash
python3 nn_ids_posture_release_checklist.py \
  --manifest /var/log/nn_ids_posture_bundle_manifest.json \
  --format json \
  --output /var/log/nn_ids_posture_release_checklist.json
```

Use `--output -` to print to stdout.

## Output contract

JSON output uses `schema_version: 1` and includes:

- `component`: always `nn_ids_posture_release_checklist`;
- `source_component` and `source_generated_at`: provenance from the input manifest;
- `status`: `pass`, `warn`, or `fail`;
- `ok`: true only when all required checklist items pass;
- `summary.failed_required_items`: checklist IDs that block promotion;
- `checklist`: required and advisory items with status, evidence, and action fields;
- `privacy_note` and `rollback` guidance.

Markdown output renders the same checklist in a manager-friendly format that can be attached to release notes or incident handoff packets.

## Security and privacy rationale

This utility is passive and local. It does not open sockets, run commands, restart services, mutate firewall rules, modify models, or change host/VM configuration. It consumes only aggregate manifest metadata such as status, control IDs, timestamps, freshness state, and artifact names.

Do not attach raw packet captures, payloads, credentials, hostnames, usernames, secrets, or raw IDS logs to the generated checklist. Use the checklist to point operators toward the evidence artifact that must be regenerated or reviewed.

## Compatibility

The checklist composes the existing `nn_ids_posture_bundle_manifest.py` JSON contract. Existing manifest JSON and Markdown workflows remain supported and do not need migration.

## Rollback

Stop generating the checklist and continue consuming `nn_ids_posture_bundle_manifest.py` JSON or Markdown output directly. No service state or host/VM configuration is changed by this tool.

## Follow-up work

- Wire checklist JSON into the aggregate hardening posture release gate.
- Add optional firstboot packaging once the release team decides where handoff artifacts should be stored.
- Surface checklist status in the GUI/dashboard without embedding sensitive raw telemetry.
