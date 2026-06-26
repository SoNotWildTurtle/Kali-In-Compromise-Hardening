# NN IDS Drift Triage

`nn_ids_drift_triage.py` converts aggregate drift evidence from `nn_ids_drift_evidence.py` into operator-friendly Markdown or compact JSON.

## Defensive scope

- Read-only: the tool only reads a local JSON evidence file and optionally writes a triage artifact.
- Privacy-safe: output is based on aggregate feature statistics and does not include packets, payloads, credentials, host secrets, or raw captures.
- Release-gate compatible: `--require-pass` exits non-zero when the source evidence is `warn` or `fail`, allowing CI or local promotion gates to stop unsafe rollouts.

## Example

```bash
python3 nn_ids_drift_evidence.py \
  --baseline /opt/nnids/baseline_feature_stats.json \
  --current /var/log/nnids/current_feature_stats.json \
  --output /var/log/nnids/drift_evidence.json

python3 nn_ids_drift_triage.py \
  --evidence /var/log/nnids/drift_evidence.json \
  --format markdown \
  --output /var/log/nnids/drift_triage.md \
  --require-pass
```

## Operator handoff fields

The JSON format includes:

- `component`: always `nn_ids_drift_triage`.
- `status` and `ok`: copied from the source evidence for promotion decisions.
- `summary`: counts of failed, warning, passing, and total features.
- `recommended_actions`: bounded next steps for failed or warning features.
- `privacy_note`: reminder that the artifact is aggregate-only.
- `rollback`: safe rollback guidance.
- `features`: sorted feature evidence with PSI, mean-shift, missing-rate delta, and messages.

## Threat-model rationale

Feature drift can indicate benign workload change, capture pipeline breakage, model/input mismatch, or adversarial pressure against the IDS. This renderer makes those signals easier to review during release gates and incident handoffs while preserving the raw JSON evidence for automation.

## Compatibility and rollback

The tool uses only the Python standard library and does not require root. Rollback is simply removing generated triage artifacts and continuing to consume raw `nn_ids_drift_evidence.py` JSON.

## Follow-up work

- Add dashboard ingestion for triage summaries.
- Add firstboot packaging once the repository has a stable install manifest for the drift evidence workflow.
- Add signed artifact manifests for drift evidence and triage bundles.
