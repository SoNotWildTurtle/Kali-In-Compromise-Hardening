#!/usr/bin/env bash
# Static validation for channel-policy evidence summary tooling.
set -euo pipefail

python3 -m py_compile channel_policy_health_summary.py

grep -q 'Summarize host/VM channel-policy JSON evidence artifacts' channel_policy_health_summary.py
grep -q 'never opens network sockets' channel_policy_health_summary.py
grep -q 'def summarize_evidence' channel_policy_health_summary.py
grep -q 'def render_json' channel_policy_health_summary.py
grep -q -- '--require-pass' channel_policy_health_summary.py
grep -q 'Missing evidence file' channel_policy_health_summary.py
grep -q 'Host/VM channel policy evidence summary' channel_policy_health_summary.py

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat >"$tmpdir/pass.json" <<'JSON'
{
  "ok": true,
  "findings": [
    {"control": "management_target", "level": "pass", "message": "private target"},
    {"control": "require_time_sync", "level": "pass", "message": "enabled"}
  ]
}
JSON

cat >"$tmpdir/fail.json" <<'JSON'
{
  "ok": false,
  "findings": [
    {"control": "allow_password_authentication", "level": "fail", "message": "password automation enabled"},
    {"control": "max_session_minutes", "level": "warn", "message": "long session"}
  ]
}
JSON

python3 channel_policy_health_summary.py "$tmpdir/pass.json" --require-pass
if python3 channel_policy_health_summary.py "$tmpdir/fail.json" --require-pass >/tmp/channel_policy_fail.out 2>/tmp/channel_policy_fail.err; then
  echo "expected failing evidence to return non-zero with --require-pass" >&2
  exit 1
fi

python3 channel_policy_health_summary.py "$tmpdir/pass.json" "$tmpdir/fail.json" --json >"$tmpdir/summary.json"
grep -q '"ok": false' "$tmpdir/summary.json"
grep -q '"failing_controls"' "$tmpdir/summary.json"
grep -q 'allow_password_authentication' "$tmpdir/summary.json"

echo "channel policy health summary static tests passed"
