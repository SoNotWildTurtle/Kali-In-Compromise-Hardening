#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/nn_ids_health_evidence.py"
SERVICE="${ROOT_DIR}/nn_ids_health_evidence.service"
TIMER="${ROOT_DIR}/nn_ids_health_evidence.timer"
BUILD_SCRIPT="${ROOT_DIR}/build_custom_iso.sh"
FIRSTBOOT="${ROOT_DIR}/firstboot.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 -m py_compile "${SCRIPT}"
python3 "${SCRIPT}" --help >/dev/null

# Normalize source whitespace before checking the documented passive-safety
# contract. This avoids brittle failures when Python formatters wrap a
# docstring across lines without changing its meaning.
python3 - "${SCRIPT}" <<'PY'
from pathlib import Path
import sys

source = " ".join(Path(sys.argv[1]).read_text(encoding="utf-8").split())
required_phrases = (
    "never opens network sockets",
    "never executes system commands",
    "hardening_posture_summary.py",
    "--require-pass",
)
missing = [phrase for phrase in required_phrases if phrase not in source]
if missing:
    raise SystemExit(f"missing passive-safety contract phrase(s): {', '.join(missing)}")
PY

for packaged in \
  "nn_ids_health_evidence.py" \
  "nn_ids_health_evidence.service" \
  "nn_ids_health_evidence.timer"; do
  grep -q -- "\"${packaged}\"" "${BUILD_SCRIPT}"
done

grep -q "systemctl enable --now nn_ids_health_evidence.timer" "${FIRSTBOOT}"
grep -q "nn_ids_health_evidence.firstboot.json" "${FIRSTBOOT}"

grep -q '^NoNewPrivileges=true' "${SERVICE}"
grep -q '^PrivateTmp=true' "${SERVICE}"
grep -q '^ProtectSystem=full' "${SERVICE}"
grep -q '^ProtectHome=true' "${SERVICE}"
grep -q '^CapabilityBoundingSet=$' "${SERVICE}"
grep -q '^ReadWritePaths=/var/log' "${SERVICE}"
grep -q '^ReadOnlyPaths=/opt/nnids' "${SERVICE}"
grep -q -- '--output /var/log/nn_ids_health_evidence.json' "${SERVICE}"
grep -q '^Persistent=true' "${TIMER}"
grep -q '^Unit=nn_ids_health_evidence.service' "${TIMER}"

MODEL="${TMP_DIR}/ids_model.pkl"
TRAIN_LOG="${TMP_DIR}/nn_ids_train.log"
HEALTH_LOG="${TMP_DIR}/nn_ids_health.log"
OUTPUT_JSON="${TMP_DIR}/nn_ids_health.json"

printf 'model-bytes\n' > "${MODEL}"
printf 'Retrain accuracy: 0.93 f1: 0.90\n' > "${TRAIN_LOG}"
printf '2026-01-01T00:00:00 healthy\n' > "${HEALTH_LOG}"

python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --max-model-age-hours 999999 \
  --min-accuracy 0.7 \
  --min-f1 0.7 \
  --output "${OUTPUT_JSON}" \
  --require-pass

python3 - "${OUTPUT_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["component"] == "nn_ids"
assert payload["status"] == "pass"
assert payload["ok"] is True
assert payload["metrics"]["accuracy"] == 0.93
assert payload["metrics"]["f1"] == 0.90
controls = {finding["control"] for finding in payload["findings"]}
assert "nn_ids.model.present" in controls
assert "nn_ids.metrics.thresholds" in controls
PY

printf 'Retrain accuracy: 0.61 f1: 0.55\n' > "${TRAIN_LOG}"
if python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --max-model-age-hours 999999 \
  --min-accuracy 0.7 \
  --min-f1 0.7 \
  --require-pass >/dev/null; then
  echo "expected low metrics to fail with --require-pass" >&2
  exit 1
fi

python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --max-model-age-hours 999999 \
  --min-accuracy 0.7 \
  --min-f1 0.7 \
  --output "${OUTPUT_JSON}" >/dev/null
python3 - "${OUTPUT_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["status"] == "fail"
assert "nn_ids.metrics.accuracy" in payload["failing_controls"]
assert "nn_ids.metrics.f1" in payload["failing_controls"]
PY

printf 'Retrain accuracy: 0.93 f1: 0.90\n' > "${TRAIN_LOG}"
printf '2026-01-01T00:00:00 restarted after supervised recovery\n' > "${HEALTH_LOG}"
python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --max-model-age-hours 999999 \
  --output "${OUTPUT_JSON}" >/dev/null
python3 - "${OUTPUT_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["status"] == "warn"
assert "nn_ids.health_log.restarts" in payload["warning_controls"]
PY

rm -f "${MODEL}"
if python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --max-model-age-hours 999999 \
  --require-pass >/dev/null; then
  echo "expected a missing model to fail with --require-pass" >&2
  exit 1
fi

echo "nn_ids_health_evidence static smoke checks passed"
