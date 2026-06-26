#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/nn_ids_health_evidence.py"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 -m py_compile "${SCRIPT}"
python3 "${SCRIPT}" --help >/dev/null

grep -q "never opens network sockets" "${SCRIPT}"
grep -q "never executes system commands" "${SCRIPT}"
grep -q "hardening_posture_summary.py" "${SCRIPT}"
grep -q -- "--require-pass" "${SCRIPT}"

MODEL="${TMP_DIR}/ids_model.pkl"
TRAIN_LOG="${TMP_DIR}/nn_ids_train.log"
HEALTH_LOG="${TMP_DIR}/nn_ids_health.log"
CAPTURE="${TMP_DIR}/live_capture.csv"
DATASET="${TMP_DIR}/dataset.csv"
PASS_JSON="${TMP_DIR}/pass.json"
FAIL_JSON="${TMP_DIR}/fail.json"
WARN_JSON="${TMP_DIR}/warn.json"

printf 'model-bytes\n' > "${MODEL}"
printf 'Train accuracy: 0.91 f1: 0.88\nRetrain accuracy: 0.93 f1: 0.90\n' > "${TRAIN_LOG}"
printf '2026-01-01T00:00:00 healthy\n' > "${HEALTH_LOG}"
printf 'len,ttl,dport,flags,label\n60,64,443,S,0\n' > "${DATASET}"
printf '60,64,443,S,0\n' > "${CAPTURE}"

python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --capture "${CAPTURE}" \
  --base-dataset "${DATASET}" \
  --max-model-age-hours 999999 \
  --min-accuracy 0.7 \
  --min-f1 0.7 \
  --output "${PASS_JSON}" \
  --require-pass

python3 - "${PASS_JSON}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["component"] == "nn_ids"
assert payload["status"] == "pass"
assert payload["ok"] is True
assert payload["metrics"]["accuracy"] == 0.93
assert payload["metrics"]["f1"] == 0.90
controls = {finding["control"] for finding in payload["findings"]}
assert "nn_ids.model.present" in controls
assert "nn_ids.metrics.thresholds" in controls
PY

printf 'Retrain accuracy: 0.50 f1: 0.40\n' > "${TRAIN_LOG}"
set +e
python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --capture "${CAPTURE}" \
  --base-dataset "${DATASET}" \
  --max-model-age-hours 999999 \
  --min-accuracy 0.7 \
  --min-f1 0.7 \
  --output "${FAIL_JSON}" \
  --require-pass
LOW_METRIC_EXIT="$?"
set -e
[[ "${LOW_METRIC_EXIT}" -ne 0 ]] || { echo "expected low metrics to fail --require-pass" >&2; exit 1; }

python3 - "${FAIL_JSON}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["status"] == "fail"
assert payload["ok"] is False
assert "nn_ids.metrics.accuracy" in payload["failing_controls"]
assert "nn_ids.metrics.f1" in payload["failing_controls"]
PY

printf 'Retrain accuracy: 0.93 f1: 0.90\n' > "${TRAIN_LOG}"
printf '2026-01-01T00:00:00 nn_ids.service restarted successfully\n' > "${HEALTH_LOG}"
set +e
python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --capture "${CAPTURE}" \
  --base-dataset "${DATASET}" \
  --max-model-age-hours 999999 \
  --min-accuracy 0.7 \
  --min-f1 0.7 \
  --output "${WARN_JSON}" \
  --require-pass
WARN_EXIT="$?"
set -e
[[ "${WARN_EXIT}" -ne 0 ]] || { echo "expected restart marker to fail --require-pass" >&2; exit 1; }

python3 - "${WARN_JSON}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["status"] == "warn"
assert payload["ok"] is False
assert "nn_ids.health_log.restarts" in payload["warning_controls"]
PY

echo "nn_ids_health_evidence static and behavior checks passed"
