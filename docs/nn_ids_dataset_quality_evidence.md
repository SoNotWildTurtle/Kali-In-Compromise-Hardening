# NN IDS dataset-quality evidence

`nn_ids_dataset_quality_evidence.py` is a passive, read-only evidence helper for release review, firstboot handoff, and recovery decisions. It inspects aggregate CSV quality signals before IDS retraining or image promotion so operators can catch malformed, tiny, single-class, heavily imbalanced, duplicate-heavy, or missing-heavy datasets without embedding raw rows or packet payloads in handoff artifacts.

## Why this matters

ML-backed IDS reliability depends on dataset relevance and quality, not only model accuracy. Recent IDS dataset evaluation research highlights the need to account for coverage, class balance, and operational relevance, while NIST-style monitoring controls emphasize auditable evidence for security monitoring and anomaly detection. This helper converts those concerns into a small local contract that can feed release gates without adding network activity or state mutation.

## Usage

```bash
python3 nn_ids_dataset_quality_evidence.py \
  --dataset /opt/nnids/datasets/dataset.csv \
  --label-column label \
  --output /var/log/nn_ids_dataset_quality_evidence.json \
  --require-pass
```

Markdown handoff output is also supported:

```bash
python3 nn_ids_dataset_quality_evidence.py \
  --dataset /opt/nnids/datasets/dataset.csv \
  --format markdown \
  --output /var/log/nn_ids_dataset_quality_evidence.md
```

## Evidence contract

The JSON output includes:

- `component`: always `nn_ids_dataset_quality`.
- `status` / `ok`: release-gate result.
- `dataset_sha256`: file digest for reproducible review.
- `thresholds`: policy thresholds used for the decision.
- `summary`: aggregate row, column, label, missing-cell, duplicate-sample, and numeric-feature counts.
- `findings`: per-control pass, warn, or fail entries.
- `failing_controls` / `warning_controls`: machine-readable blockers.
- `privacy`: explicit statement that raw rows and packet payloads are excluded.

## Default checks

- Dataset file exists and is readable.
- CSV header is present and includes the configured label column.
- Minimum row count defaults to `100`.
- Minimum non-empty class count defaults to `2`.
- Missing-cell rate defaults to at most `0.05`.
- Majority-class ratio defaults to at most `0.95`.
- Duplicate sampled-row rate defaults to at most `0.20`.
- Column count warns above `256` for manual review.
- Numeric feature ratio warns above `0.98` to prompt review for identifiers, timestamps, or leaked labels.

## Threat-model rationale

This helper is defensive and privacy-preserving. It never opens network sockets, executes system commands, changes firewall rules, mutates service state, modifies model files, approves restores, or rewrites datasets. It gives operators a reversible aggregate signal that can be reviewed before retraining or promotion.

## Compatibility

The helper uses only the Python standard library. It is optional and additive. Existing IDS training, capture, health evidence, drift evidence, model-card, and posture-release workflows remain authoritative until consumers explicitly adopt this additional signal.

## Rollback

Remove `nn_ids_dataset_quality_evidence.py` from `build_custom_iso.sh` if the optional helper is not needed. No persistent runtime state or migration is introduced.

## Follow-up work

- Add a timer/service once operators decide on a preferred cadence and storage path.
- Feed the JSON into `nn_ids_posture_bundle_manifest.py` as optional evidence.
- Add dataset lineage fields for source, collection window, and ATT&CK coverage when upstream metadata exists.
