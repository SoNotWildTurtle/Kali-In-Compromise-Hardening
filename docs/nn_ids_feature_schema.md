# NN IDS Feature Schema and Drift Guardrails

This defensive note documents the current feature contract for the Kali NN IDS. The goal is to make model training, live packet inference, audit review, rollback, and future PRs use the same feature order instead of relying on implicit dataframe or packet-field ordering.

## Canonical feature order

The live IDS and trainer now share this ordered feature vector:

1. `len` - IP packet length, expected range `1..65535`.
2. `ttl` - IP time-to-live, expected range `0..255`.
3. `dport` - TCP destination port, expected range `0..65535`.
4. `tcp_flags` - integer TCP flag value, expected range `0..255`.

Training datasets must also include `label`. Extra columns are ignored by the trainer after validation so the model does not silently learn a different feature order.

## Why this matters

A neural IDS can fail open if training and inference disagree about feature order or range. This change treats feature order as a security contract and validates live packet vectors before inference. It also gives the suite a durable `/opt/nnids/feature_schema.json` artifact that can be reviewed during incident response, compared across snapshots, and used as a stable input to future drift and explainability work.

## Defensive controls added

- `nn_ids_feature_schema.py` defines the canonical schema, validates dataset columns, validates live vectors, writes the schema artifact, and includes a small population-stability-index helper for drift scoring.
- `nn_ids_setup.py` uses the canonical feature order, removes duplicate sanitizer/model-save paths, stores precision and recall alongside accuracy and F1, applies deterministic noise augmentation, and trains through a standard scaler plus MLP pipeline.
- `nn_ids_service.py` now performs one prediction path, validates live vectors before inference, keeps probability thresholds configurable, and avoids duplicate alert writes.
- `tests/test_nn_ids_feature_schema_static.sh` checks feature order, missing-column detection, range rejection, and drift-score behavior.

## Follow-up work

The next high-value increment is to persist rolling live-feature windows, compare them against training baselines with PSI or Jensen-Shannon distance, and gate automatic blocking when drift is high so the IDS does not overreact to a changed but benign network environment.
