#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

evidence="${tmpdir}/drift_evidence.json"
triage_json="${tmpdir}/drift_triage.json"
triage_md="${tmpdir}/drift_triage.md"

cat >"${evidence}" <<'JSON'
{
  "component": "nn_ids_drift",
  "generated_at": "2026-06-26T12:00:00+00:00",
  "status": "warn",
  "ok": false,
  "features": [
    {
      "feature": "ttl",
      "status": "warn",
      "psi": 0.13,
      "mean_shift_sigma": 2.5,
      "missing_rate_delta": 0.01,
      "messages": ["PSI exceeded warning threshold"]
    },
    {
      "feature": "len",
      "status": "pass",
      "psi": 0.01,
      "mean_shift_sigma": 0.2,
      "missing_rate_delta": 0.0,
      "messages": ["feature drift is within configured thresholds"]
    }
  ]
}
JSON

python3 -m py_compile nn_ids_drift_triage.py

if python3 nn_ids_drift_triage.py --evidence "${evidence}" --format json --output "${triage_json}" --require-pass; then
  echo "expected --require-pass to fail for warn evidence" >&2
  exit 1
fi

python3 nn_ids_drift_triage.py --evidence "${evidence}" --format markdown --output "${triage_md}"

grep -q '"component": "nn_ids_drift_triage"' "${triage_json}"
grep -q '"warning_features": 1' "${triage_json}"
grep -q 'Pause promotion' "${triage_json}" || grep -q 'Track `ttl`' "${triage_json}"
grep -q '# NN IDS Drift Triage' "${triage_md}"
grep -q '| ttl | warn | 0.130 | 2.500 | 0.010 |' "${triage_md}"
grep -q 'Privacy:' "${triage_md}"
grep -q 'Rollback:' "${triage_md}"
