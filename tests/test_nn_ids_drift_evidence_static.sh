#!/usr/bin/env bash
# MINC - Static checks for NN IDS drift evidence emission.
# Defensive validation only: keeps drift gates passive, explainable, and machine-readable.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$TMP_DIR/baseline.json" <<'JSON'
{
  "features": {
    "len": {"mean": 100.0, "std": 10.0, "missing_rate": 0.0, "samples": [90, 95, 100, 105, 110, 115, 120, 125, 130, 135, 140, 145]},
    "ttl": {"mean": 64.0, "std": 4.0, "missing_rate": 0.0, "samples": [60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71]},
    "dport": {"mean": 443.0, "std": 1.0, "missing_rate": 0.0, "samples": [443, 443, 443, 443, 443, 443, 443, 443, 443, 443, 443, 443]},
    "tcp_flags": {"mean": 18.0, "std": 1.0, "missing_rate": 0.0, "samples": [18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18]}
  }
}
JSON

cat >"$TMP_DIR/current-pass.json" <<'JSON'
{
  "features": {
    "len": {"mean": 100.5, "std": 10.0, "missing_rate": 0.0, "samples": [90, 95, 100, 105, 110, 115, 120, 125, 130, 135, 140, 145]},
    "ttl": {"mean": 64.2, "std": 4.0, "missing_rate": 0.0, "samples": [60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71]},
    "dport": {"mean": 443.0, "std": 1.0, "missing_rate": 0.0, "samples": [443, 443, 443, 443, 443, 443, 443, 443, 443, 443, 443, 443]},
    "tcp_flags": {"mean": 18.0, "std": 1.0, "missing_rate": 0.0, "samples": [18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18]}
  }
}
JSON

cat >"$TMP_DIR/current-fail.json" <<'JSON'
{
  "features": {
    "len": {"mean": 190.0, "std": 12.0, "missing_rate": 0.20, "samples": [180, 185, 190, 195, 200, 205, 210, 215, 220, 225, 230, 235]},
    "ttl": {"mean": 64.0, "std": 4.0, "missing_rate": 0.0, "samples": [60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71]},
    "dport": {"mean": 443.0, "std": 1.0, "missing_rate": 0.0, "samples": [443, 443, 443, 443, 443, 443, 443, 443, 443, 443, 443, 443]},
    "tcp_flags": {"mean": 18.0, "std": 1.0, "missing_rate": 0.0, "samples": [18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18]}
  }
}
JSON

python3 -m py_compile nn_ids_drift_evidence.py
python3 nn_ids_drift_evidence.py \
  --baseline "$TMP_DIR/baseline.json" \
  --current "$TMP_DIR/current-pass.json" \
  --require-pass \
  --output "$TMP_DIR/pass-evidence.json"

python3 - <<'PY' "$TMP_DIR/pass-evidence.json"
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload["component"] != "nn_ids_drift" or payload["status"] != "pass" or not payload["ok"]:
    raise SystemExit(f"unexpected pass payload: {payload}")
if len(payload.get("features", [])) != 4:
    raise SystemExit("expected canonical four-feature drift evidence")
PY

if python3 nn_ids_drift_evidence.py \
  --baseline "$TMP_DIR/baseline.json" \
  --current "$TMP_DIR/current-fail.json" \
  --require-pass \
  --output "$TMP_DIR/fail-evidence.json"; then
  echo "expected drift failure when --require-pass is set" >&2
  exit 1
fi

python3 - <<'PY' "$TMP_DIR/fail-evidence.json"
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload["status"] != "fail" or payload["ok"]:
    raise SystemExit(f"unexpected fail payload: {payload}")
if "nn_ids.drift.len" not in payload.get("failing_controls", []):
    raise SystemExit("len drift failure control was not emitted")
PY

echo "[static-check] NN IDS drift evidence checks passed"
