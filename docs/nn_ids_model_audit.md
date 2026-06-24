# NN IDS model audit

`nn_ids_model_audit.py` is a defensive quality gate for the Kali neural-network IDS. It evaluates the locally trained model against the local cleaned dataset and writes a JSON report to `/var/log/nn_ids_model_audit.json`.

## Why this exists

The IDS already trains and runs a neural-network classifier, but operational IDS models need ongoing checks beyond a single accuracy number. Current intrusion-detection and cybersecurity-ML research continues to emphasize four practical failure modes:

- class imbalance, where high accuracy can hide poor malicious-class recall;
- concept drift, where traffic and attack patterns change after deployment;
- perturbation/adversarial fragility, where small feature changes can degrade detection;
- explainability drift, where the model starts depending on different features than expected.

This audit module turns those concerns into a local, repeatable report without changing the live detection path.

## What it measures

The audit records:

- row count, feature names, and class distribution;
- accuracy, balanced accuracy, precision, recall, F1, and confusion matrix;
- baseline feature statistics and feature mean-shift drift;
- a lightweight robustness index across small Gaussian perturbation levels;
- permutation-importance feature ranking and top-feature drift.

## Files

- `/usr/local/bin/nn_ids_model_audit.py` - audit runner.
- `/etc/systemd/system/nn_ids_model_audit.service` - locked-down one-shot service.
- `/etc/systemd/system/nn_ids_model_audit.timer` - daily timer.
- `/opt/nnids/audit/baseline_feature_stats.json` - first-run drift baseline.
- `/opt/nnids/audit/baseline_feature_importance.json` - first-run explainability baseline.
- `/var/log/nn_ids_model_audit.json` - latest report.

## Safe operation

The script reads only local IDS artifacts. It does not generate network traffic, scan hosts, attempt evasion, alter firewall rules, or contact outside systems. It exits non-zero and writes a failure report when required model or dataset files are missing.

## Usage

Run manually:

```bash
sudo /usr/local/bin/nn_ids_model_audit.py
```

Enable the scheduled audit:

```bash
sudo systemctl enable --now nn_ids_model_audit.timer
```

Review the latest report:

```bash
sudo cat /var/log/nn_ids_model_audit.json
```

## Interpreting results

- Prefer `balanced_accuracy`, `recall`, and `f1` over raw accuracy when classes are imbalanced.
- Treat `drift.shifted_features` as a prompt to review data quality and retraining assumptions.
- Treat a falling `robustness.robustness_index` as a signal to revisit feature engineering, regularization, and augmentation.
- Treat large `explainability.importance_drift.top_feature_changes` as a reason to inspect whether the model has become dependent on unstable or easily manipulated features.

## Next integration path

Future runs should wire this report into `nn_ids_report.py`, add thresholds to `/etc/nn_ids.conf`, and optionally trigger safe retraining or rollback when drift or robustness degradation crosses a configured limit.
