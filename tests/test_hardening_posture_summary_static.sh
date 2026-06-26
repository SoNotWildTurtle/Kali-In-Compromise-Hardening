#!/usr/bin/env bash
# Static and behavior validation for the aggregate hardening posture summary.
set -euo pipefail

python3 -m py_compile hardening_posture_summary.py

grep -q 'Aggregate defensive Kali hardening component health' hardening_posture_summary.py
grep -q 'never opens network sockets' hardening_posture_summary.py
grep -q 'def summarize_component' hardening_posture_summary.py
grep -q 'def posture_state' hardening_posture_summary.py
grep -q 'Posture summary error' hardening_posture_summary.py
grep -q -- '--require-pass' hardening_posture_summary.py
grep -q 'Kali hardening posture summary' hardening_posture_summary.py

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

cat >"${tmp_dir}/channel-policy-summary.json" <<'JSON'
{
  "component": "channel-policy",
  "ok": true,
  "status": "pass",
  "message": "host/VM channel policy passed",
  "failing_controls": [],
  "warning_controls": []
}
JSON

cat >"${tmp_dir}/ids-health.json" <<'JSON'
{
  "component": "nn-ids",
  "ok": true,
  "status": "warn",
  "message": "model drift score approaching review threshold",
  "failing_controls": [],
  "warning_controls": ["drift_score"]
}
JSON

cat >"${tmp_dir}/snapshot-health.json" <<'JSON'
{
  "component": "snapshot",
  "ok": false,
  "findings": [
    {"level": "fail", "control": "known_good_snapshot_present"}
  ]
}
JSON

python3 hardening_posture_summary.py "${tmp_dir}/channel-policy-summary.json" --require-pass >/dev/null

if python3 hardening_posture_summary.py "${tmp_dir}/ids-health.json" --require-pass >/dev/null 2>&1; then
  echo 'warning posture unexpectedly passed --require-pass' >&2
  exit 1
fi

if python3 hardening_posture_summary.py "${tmp_dir}/snapshot-health.json" --require-pass >/dev/null 2>&1; then
  echo 'failing posture unexpectedly passed --require-pass' >&2
  exit 1
fi

python3 hardening_posture_summary.py "${tmp_dir}"/*.json --json >"${tmp_dir}/posture.json"
grep -q '"component": "channel-policy"' "${tmp_dir}/posture.json"
grep -q '"component": "nn-ids"' "${tmp_dir}/posture.json"
grep -q '"status": "fail"' "${tmp_dir}/posture.json"
grep -q 'known_good_snapshot_present' "${tmp_dir}/posture.json"

cat >"${tmp_dir}/malformed.json" <<'JSON'
[
  "not an object"
]
JSON

if python3 hardening_posture_summary.py "${tmp_dir}/malformed.json" >/dev/null 2>"${tmp_dir}/malformed.err"; then
  echo 'malformed posture input unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'Posture summary error' "${tmp_dir}/malformed.err"
