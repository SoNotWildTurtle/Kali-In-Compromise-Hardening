# NN IDS model card

`nn_ids_model_card.py` generates a privacy-safe model card from existing aggregate NN IDS release artifacts. It is intended for release gates, firstboot review, recovery handoffs, and operator audits where reviewers need to understand whether the current model evidence is safe to promote without opening raw captures or sensitive logs.

## Inputs

The tool reads these artifacts by default:

- `/opt/nnids/feature_schema.json` from the canonical feature-schema contract.
- `/var/log/nn_ids_health_evidence.json` from the passive health evidence emitter.
- `/var/log/nn_ids_drift_evidence.json` from the passive drift evidence emitter.
- `/var/log/nn_ids_posture_release_receipt.json` from the posture release receipt.

Each input is optional at runtime, but missing or unreadable inputs become explicit blockers in the generated card.

## Usage

```bash
python3 nn_ids_model_card.py --output /var/log/nn_ids_model_card.json --require-pass
python3 nn_ids_model_card.py --format markdown --output /var/log/nn_ids_model_card.md
```

Use custom paths during tests, recovery, or offline review:

```bash
python3 nn_ids_model_card.py \
  --schema ./artifacts/feature_schema.json \
  --health ./artifacts/nn_ids_health_evidence.json \
  --drift ./artifacts/nn_ids_drift_evidence.json \
  --receipt ./artifacts/nn_ids_posture_release_receipt.json \
  --format markdown \
  --output ./artifacts/nn_ids_model_card.md \
  --require-pass
```

## Output contract

The JSON output uses `component: nn_ids_model_card` and `schema_version: 1`. It records:

- feature order and feature count;
- aggregate health status and safe metric values;
- aggregate drift status plus failing/warning feature names;
- release receipt decision;
- blockers and operator actions;
- privacy and rollback notes.

`--require-pass` exits non-zero unless all required aggregate evidence is present and passing and the release receipt is approved.

## Threat-model rationale

The model card helps prevent silent model promotion when training/inference schema, health evidence, drift evidence, or release receipts are stale, missing, or failing. It supports least-privilege release review by avoiding raw packet captures, raw IDS logs, hostnames, usernames, credentials, secrets, model binaries, and host/VM state.

This is a defensive analytical control only. It does not claim that model output is certain, does not identify people or targets, and does not authorize automatic blocking. Operators should use it as one release-readiness artifact alongside source review, CI checks, service health, rollback plans, and human approval.

## Compatibility

The tool is read-only and uses only the Python standard library. It writes either JSON or Markdown to the requested output path and does not open network sockets, run subprocesses, restart services, alter firewall rules, mutate model files, change datasets, or change host/VM configuration.

## Rollback

Stop invoking `nn_ids_model_card.py` and continue reviewing the existing feature schema, health evidence, drift evidence, posture checklist, and release receipt artifacts directly. No deployed control needs to be disabled because the model-card generator is passive.

## Follow-up work

- Package the model card into firstboot/release-gate workflows once CI validates the standalone contract.
- Add dashboard links that render the Markdown card without exposing sensitive telemetry.
- Include signed artifact references when the suite gains an attestation store.
