# NN IDS posture bundle manifest

`nn_ids_posture_bundle_manifest.py` creates one privacy-safe JSON manifest from the existing NN IDS health, drift, and drift-triage evidence files. It is intended for release gates, handoffs, dashboards, and maintenance review where an operator needs to know whether the IDS evidence set is complete enough to trust without opening raw logs or captures.

## Inputs

By default the helper reads:

- `/var/log/nn_ids_health_evidence.json` from `nn_ids_health_evidence.py`
- `/var/log/nn_ids_drift_evidence.json` from `nn_ids_drift_evidence.py`
- `/var/log/nn_ids_drift_triage.json` from `nn_ids_drift_triage.py --format json`

All inputs can be overridden for CI fixtures or staged release artifacts:

```bash
python3 nn_ids_posture_bundle_manifest.py \
  --health-evidence ./artifacts/nn_ids_health_evidence.json \
  --drift-evidence ./artifacts/nn_ids_drift_evidence.json \
  --drift-triage ./artifacts/nn_ids_drift_triage.json \
  --output ./artifacts/nn_ids_posture_bundle_manifest.json
```

Use `--output -` to print the manifest to stdout.

## Operator handoff report

Use `--format markdown` when a human reviewer or on-call operator needs a privacy-safe handoff rather than a machine contract:

```bash
python3 nn_ids_posture_bundle_manifest.py \
  --health-evidence ./artifacts/nn_ids_health_evidence.json \
  --drift-evidence ./artifacts/nn_ids_drift_evidence.json \
  --drift-triage ./artifacts/nn_ids_drift_triage.json \
  --format markdown \
  --output ./artifacts/nn_ids_posture_bundle_handoff.md
```

The Markdown report includes the aggregate release-gate verdict, artifact presence, component names, generated timestamps, short SHA-256 digests, promotion blockers, promotion warnings, privacy notes, and rollback guidance. It intentionally does not embed raw packet captures, payloads, hostnames, usernames, credentials, secrets, or raw IDS logs.

## Release-gate behavior

Use `--require-pass` when the manifest is feeding a promotion or release gate:

```bash
python3 nn_ids_posture_bundle_manifest.py --require-pass
```

The command exits non-zero when any required artifact is missing, malformed, unreadable, or reports a failing status. Warning statuses are preserved as promotion warnings so reviewers can decide whether a baseline refresh or additional investigation is needed before shipping. This exit behavior is identical for JSON and Markdown output.

## Manifest schema

The generated JSON includes:

- `component`: `nn_ids_posture_bundle_manifest`
- `schema_version`: manifest contract version
- `status` and `ok`: aggregate pass/warn/fail verdict
- `artifacts`: per-artifact existence, component, status, generated timestamp, and SHA-256 digest
- `summary`: present/missing artifact counts plus merged failing and warning controls
- `release_gate`: machine-readable promotion blockers and warnings
- `privacy_note`: explicit statement of excluded sensitive data
- `rollback`: safe fallback instructions

The Markdown renderer is a presentation layer over the same manifest contract. It does not alter the JSON schema and can be rolled back independently by returning to the default `--format json` mode.

## Threat-model rationale

The manifest is read-only and does not make security-control changes. It hashes evidence artifacts and aggregates statuses so review tooling can detect stale, missing, or degraded IDS evidence without embedding packets, payloads, credentials, hostnames, usernames, raw captures, or secrets in handoff material.

This supports secure-by-default release gating: model or VM promotion can depend on health and drift evidence being present, current, and reviewable without conflating analytical drift with operational certainty. The Markdown handoff improves human review while preserving the same privacy boundary as the JSON manifest.

## Compatibility

The helper only uses the Python standard library and accepts local paths, so it works in offline Kali VMs, CI fixtures, and staged release artifact directories. It composes with the existing evidence emitters instead of changing their schemas.

## Rollback

Delete the generated manifest or Markdown handoff and continue consuming the individual health, drift, and triage JSON files directly. No service, firewall, model, dataset, or host/VM configuration state is modified. If the Markdown renderer causes a downstream tooling issue, switch back to the default JSON output without changing the evidence sources.

## Follow-up work

- Package the manifest helper into firstboot or timer wiring once the team chooses the desired cadence.
- Surface the Markdown handoff in dashboards and aggregate posture summaries.
- Add CI artifact upload rules so release reviewers can download the manifest and handoff report alongside health and drift evidence.
