# NN IDS drift evidence

`nn_ids_drift_evidence.py` is a passive, local-only evidence emitter for comparing baseline and current NN IDS feature statistics. It is intended for safe release gates, dashboards, handoff notes, and incident review before model retraining or promotion.

The tool does not open network sockets, execute commands, edit firewall rules, restart services, or modify host/VM state. It reads JSON statistics and writes a machine-readable report.

## Why this exists

The IDS already has a canonical feature schema. Drift evidence adds an operational guardrail around that schema by answering:

- are current feature distributions still close to the approved baseline?
- did missing-rate behavior change enough to make model output less trustworthy?
- should a release gate warn or fail before a model, dataset, or automation bundle is promoted?

Predictive outputs should remain analytical estimates. Drift failures mean the evidence changed enough to require review, not that traffic is malicious with certainty.

## Input format

The baseline and current files are JSON objects. Feature statistics may be nested under `features` or placed at the top level by feature name.

```json
{
  "features": {
    "len": {
      "mean": 100.0,
      "std": 10.0,
      "missing_rate": 0.0,
      "samples": [90, 95, 100, 105, 110]
    }
  }
}
```

Supported per-feature fields:

- `mean`: current or baseline mean.
- `std`, `stdev`, or `sigma`: baseline spread used to normalize mean shift.
- `missing_rate`: fraction of rows missing or rejected for that feature.
- `samples` or `values`: optional numeric samples used to compute population stability index (PSI).

When `--feature` is omitted, the tool evaluates the canonical IDS feature order from `nn_ids_feature_schema.py`.

## Example

```bash
python3 nn_ids_drift_evidence.py \
  --baseline /opt/nnids/baseline_feature_stats.json \
  --current /var/lib/nnids/current_feature_stats.json \
  --output /var/log/nn_ids_drift_evidence.json
```

Release gate mode:

```bash
python3 nn_ids_drift_evidence.py \
  --baseline baseline.json \
  --current current.json \
  --require-pass
```

`--require-pass` exits non-zero when any feature crosses a fail threshold. Warnings still emit JSON evidence so operators can decide whether to retrain, collect more clean data, or roll back to a known-good model snapshot.

## Default thresholds

- PSI warning: `0.10`
- PSI failure: `0.25`
- Mean-shift warning: `2.0` baseline standard deviations
- Mean-shift failure: `4.0` baseline standard deviations
- Missing-rate warning: `0.05`
- Missing-rate failure: `0.15`

These defaults are conservative operational tripwires rather than mathematical proof of compromise. Tune them per deployment after reviewing normal traffic, capture quality, and acceptable false-positive rates.

## Output contract

The report uses the same posture-friendly fields as other evidence emitters:

- `component`: `nn_ids_drift`
- `status`: `pass`, `warn`, or `fail`
- `ok`: boolean pass indicator
- `failing_controls` and `warning_controls`: machine-readable control IDs
- `features`: per-feature PSI, mean-shift, missing-rate delta, status, and explanatory messages

This output can be passed into `hardening_posture_summary.py` with other component reports.

## Rollback

The workflow is additive and read-only. Rollback is limited to removing `nn_ids_drift_evidence.py`, this documentation, and the matching static test if the evidence format needs to be replaced.

## Follow-up work

- Wire drift evidence into the aggregate posture summary examples.
- Add a small stats exporter that derives baseline/current JSON from sanitized CSV captures.
- Surface drift status in the dashboard once stable sample artifacts exist.
