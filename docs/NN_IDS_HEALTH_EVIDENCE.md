# NN IDS Health Evidence

`nn_ids_health_evidence.py` emits a passive JSON health document for the neural-network IDS. It is designed to feed `hardening_posture_summary.py` so the suite can gate privileged hardening or release workflows on evidence from the IDS control plane instead of relying on informal log review.

## Why this exists

The repository already trains, retrains, supervises, snapshots, and monitors the NN IDS. Those components produce useful local artifacts, but operators and CI jobs need a consistent schema that can be combined with host/VM channel-policy evidence, restore-readiness evidence, port-monitor evidence, and other defensive posture checks.

This module is intentionally additive and read-only:

- It reads only local files supplied by path or the safe defaults under `/opt/nnids` and `/var/log`.
- It never opens network sockets.
- It never executes commands.
- It never restarts services, edits firewall rules, changes model files, writes policy, or modifies host/VM state.
- It exits non-zero with `--require-pass` when the model, training metrics, or health logs indicate degraded posture.

## Default evidence inputs

| Evidence | Default path | Purpose |
| --- | --- | --- |
| IDS model | `/opt/nnids/ids_model.pkl` | Confirms a trained model is present and fresh enough. |
| Training log | `/var/log/nn_ids_train.log` | Parses the latest `accuracy` and `f1` values written by training/retraining. |
| Health log | `/var/log/nn_ids_health.log` | Detects recent missing-model, restart, or failure markers. |
| Live capture | `/opt/nnids/live_capture.csv` | Records whether capture data is readable when present. |
| Base dataset | `/opt/nnids/datasets/dataset.csv` | Records whether baseline data is readable when present. |

## Usage

Generate evidence to standard output:

```bash
python3 nn_ids_health_evidence.py
```

Write a health document for posture aggregation:

```bash
python3 nn_ids_health_evidence.py \
  --output /var/log/nn_ids_health_evidence.json
```

Fail closed when the IDS posture is not fully passing:

```bash
python3 nn_ids_health_evidence.py \
  --min-accuracy 0.80 \
  --min-f1 0.80 \
  --max-model-age-hours 48 \
  --output /var/log/nn_ids_health_evidence.json \
  --require-pass
```

Combine with the aggregate hardening posture gate:

```bash
python3 hardening_posture_summary.py \
  /var/log/channel_policy_health.json \
  /var/log/nn_ids_health_evidence.json \
  --json \
  --require-pass
```

## Deployment integration

The live ISO packaging flow now includes these additive files:

- `nn_ids_health_evidence.py`
- `nn_ids_health_evidence.service`
- `nn_ids_health_evidence.timer`

On first boot, `firstboot.sh` enables `nn_ids_health_evidence.timer` when the unit is present and writes an immediate firstboot artifact to `/var/log/nn_ids_health_evidence.firstboot.json`. The timer then emits `/var/log/nn_ids_health_evidence.json` every 30 minutes after boot.

The service intentionally omits `--require-pass` so the timer keeps publishing degraded evidence instead of hiding health data behind a failed unit. Release gates and operator workflows should call the script or the aggregate posture summary with `--require-pass` when fail-closed behavior is required.

### Systemd hardening

`nn_ids_health_evidence.service` is a oneshot unit with baseline hardening controls:

- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=full`
- `ProtectHome=true`
- empty `CapabilityBoundingSet`
- `ReadOnlyPaths=/opt/nnids`
- `ReadWritePaths=/var/log`

These settings keep the emitter passive while allowing it to read IDS artifacts and write only the evidence JSON/log outputs needed by local posture aggregation.

## Schema

The JSON output follows the schema expected by `hardening_posture_summary.py`:

```json
{
  "component": "nn_ids",
  "status": "pass",
  "ok": true,
  "failing_controls": [],
  "warning_controls": [],
  "findings": []
}
```

Additional fields include thresholds, file paths, latest training metrics, model age, capture row count, dataset row count, and a timestamp.

## Threat-model rationale

The NN IDS is a defensive telemetry and detection subsystem. If the model is missing, stale, repeatedly restarting, or producing weak validation metrics, the hardening suite should expose that degraded state before trusted automation proceeds. This aligns with the repository's host/VM channel-policy direction: collect auditable local evidence, fail closed when evidence is absent or degraded, and avoid expanding privileges during health checks.

Recent zero-trust guidance and 2025 workload-identity research emphasize explicit validation, scoped automation, and policy evidence for non-human control-plane actors. This module applies that principle locally by turning IDS health into a bounded, machine-readable evidence artifact.

## Compatibility and rollback

This is an additive helper. Existing IDS training, retraining, service supervision, resource monitoring, and snapshot workflows are not changed. To roll back, remove `nn_ids_health_evidence.py`, `nn_ids_health_evidence.service`, `nn_ids_health_evidence.timer`, `tests/test_nn_ids_health_evidence_static.sh`, the `build_custom_iso.sh` packaging entries, the `firstboot.sh` timer wiring, and this document.

## Follow-up work

- Add model-drift statistics once the retraining pipeline stores a stable validation baseline.
- Add first-class health emitters for resource pressure, snapshot freshness, restore readiness, time sync, and port exposure.
- Feed `/var/log/nn_ids_health_evidence.json` into the aggregate posture summary during safe release gates once PR #40 is merged into `main`.
