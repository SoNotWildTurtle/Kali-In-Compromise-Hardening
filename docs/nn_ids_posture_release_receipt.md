# NN IDS posture release receipt

`nn_ids_posture_release_receipt.py` converts the JSON checklist from `nn_ids_posture_release_checklist.py --format json` into a final privacy-safe release, firstboot, or recovery receipt.

## Why this exists

The posture bundle and checklist already answer whether required NN IDS evidence exists, is fresh when enforced, and is ready for promotion. The receipt adds a durable operator handoff artifact that records:

- the release or recovery identifier;
- the environment being reviewed;
- the approving role or automation gate;
- an explicit `approved` or `deferred` decision;
- failed required checklist IDs and advisory warnings;
- action items for any missing, failing, unknown, or warning items.

This keeps release review auditable without embedding sensitive telemetry. The design follows secure-by-default release evidence practices: it is read-only, aggregate-only, reversible, and suitable for CI or manager handoff packets.

## Usage

Generate JSON for automation:

```bash
python3 nn_ids_posture_release_receipt.py \
  --checklist /var/log/nn_ids_posture_release_checklist.json \
  --release-id firstboot-2026-06-26 \
  --environment firstboot \
  --approver release-gate \
  --output /var/log/nn_ids_posture_release_receipt.json
```

Fail a release gate unless the checklist is ready:

```bash
python3 nn_ids_posture_release_receipt.py \
  --checklist /var/log/nn_ids_posture_release_checklist.json \
  --require-ready
```

Generate a Markdown receipt for an operator handoff:

```bash
python3 nn_ids_posture_release_receipt.py \
  --checklist /var/log/nn_ids_posture_release_checklist.json \
  --format markdown \
  --output /var/log/nn_ids_posture_release_receipt.md
```

Use `--output -` to print to stdout.

## Output contract

JSON output uses `schema_version: 1` and includes:

- `component`: always `nn_ids_posture_release_receipt`;
- `release_id`, `environment`, and `approver`: operator-supplied receipt context;
- `decision`: `approved` only when the checklist reports ready and no required item failed; otherwise `deferred`;
- `ok`: boolean form of the decision;
- `source_component`, `source_generated_at`, `source_status`, and `source_ok`: provenance from the checklist;
- `summary.failed_required_items`: blocking checklist IDs;
- `summary.warning_items`: advisory checklist IDs requiring review;
- `action_items`: remediation actions for failed, missing, unknown, or warning items;
- `receipt_contract`, `privacy_note`, and `rollback`.

Markdown output renders the same contract in a manager-friendly format.

## Security and privacy rationale

This utility is passive and local. It does not open sockets, run commands, restart services, change firewall rules, modify models, mutate datasets, alter host/VM configuration, or inspect raw telemetry.

The receipt contains aggregate checklist IDs, status fields, timestamps, decisions, and remediation text only. Do not attach raw packet captures, payloads, credentials, hostnames, usernames, secrets, model files, or raw IDS logs to the receipt.

The receipt also supports a safer release-management workflow: when `--require-ready` is used, a deferred checklist exits non-zero and can block promotion without weakening hardening controls or bypassing earlier evidence checks.

## Compatibility

The receipt composes the existing `nn_ids_posture_release_checklist.py --format json` contract. Existing posture manifest, checklist Markdown, and checklist JSON workflows remain supported.

## Rollback

Stop generating receipts and continue using `nn_ids_posture_bundle_manifest.py` plus `nn_ids_posture_release_checklist.py` directly. No service state, firewall state, model artifact, dataset, host setting, VM setting, or network path is changed by this utility.

## Follow-up work

- Wire the receipt JSON into the aggregate hardening posture release gate.
- Add firstboot packaging once operators decide the canonical receipt storage path.
- Surface receipt decision status in the dashboard without embedding sensitive raw telemetry.
