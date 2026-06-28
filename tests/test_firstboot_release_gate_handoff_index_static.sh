#!/usr/bin/env bash
# MINC - Static tests for passive firstboot release-gate handoff index.
# Defensive validation only: generates temporary aggregate artifacts and changes no live host/VM state.

set -euo pipefail

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

assert_file_contains() {
    local file="$1"
    local expected="$2"
    grep -Fq -- "$expected" "$file" || fail "Expected '$expected' in $file"
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile firstboot_release_gate_handoff_index.py
bash -n build_custom_iso.sh

cat >"$TMPDIR/status.json" <<'JSON'
{
  "component": "firstboot_release_gate_status",
  "ok": true,
  "decision": "approved",
  "release_gate": "pass",
  "blocker_count": 0,
  "stale_or_skewed_count": 0
}
JSON

cat >"$TMPDIR/bundle.json" <<'JSON'
{
  "component": "firstboot_release_gate_bundle_manifest",
  "ok": true,
  "decision": "approved",
  "release_gate": "pass",
  "artifacts": []
}
JSON

cat >"$TMPDIR/digest.json" <<'JSON'
{
  "component": "firstboot_release_gate_operator_digest",
  "ok": true,
  "decision": "approved",
  "release_gate": "pass"
}
JSON

printf '# Status\n' >"$TMPDIR/status.md"
printf '# Bundle\n' >"$TMPDIR/bundle.md"
printf '# Digest\n' >"$TMPDIR/digest.md"
printf 'FIRSTBOOT_RELEASE_GATE_DECISION="approved"\n' >"$TMPDIR/summary.env"

python3 firstboot_release_gate_handoff_index.py \
    --release-gate-json "$TMPDIR/missing-gate.json" \
    --release-gate-markdown "$TMPDIR/missing-gate.md" \
    --summary-env "$TMPDIR/summary.env" \
    --status-json "$TMPDIR/status.json" \
    --bundle-manifest-json "$TMPDIR/bundle.json" \
    --bundle-manifest-markdown "$TMPDIR/bundle.md" \
    --operator-digest-json "$TMPDIR/digest.json" \
    --operator-digest-markdown "$TMPDIR/digest.md" \
    --output "$TMPDIR/index.json" \
    --require-ready >/tmp/firstboot_handoff_index_pass.out

assert_file_contains "$TMPDIR/index.json" '"component": "firstboot_release_gate_handoff_index"'
assert_file_contains "$TMPDIR/index.json" '"decision": "approved"'
assert_file_contains "$TMPDIR/index.json" '"release_gate": "pass"'
assert_file_contains "$TMPDIR/index.json" '"privacy_scope": "aggregate_release_gate_handoff_index_only"'
assert_file_contains "$TMPDIR/index.json" '"safe_default": "read-only handoff index; no host, VM, firewall, service, model, dataset, approval, restore, network, or firstboot state was changed"'
assert_file_contains "$TMPDIR/index.json" '"sha256"'

python3 firstboot_release_gate_handoff_index.py \
    --status-json "$TMPDIR/status.json" \
    --bundle-manifest-json "$TMPDIR/bundle.json" \
    --operator-digest-json "$TMPDIR/digest.json" \
    --output "$TMPDIR/index.md" \
    --format markdown >/tmp/firstboot_handoff_index_markdown.out

assert_file_contains "$TMPDIR/index.md" '# Firstboot release-gate handoff index'
assert_file_contains "$TMPDIR/index.md" '## Artifact counts'
assert_file_contains "$TMPDIR/index.md" 'Privacy exclusions'
assert_file_contains "$TMPDIR/index.md" 'Rollback'

if python3 firstboot_release_gate_handoff_index.py \
    --status-json "$TMPDIR/missing-status.json" \
    --bundle-manifest-json "$TMPDIR/bundle.json" \
    --operator-digest-json "$TMPDIR/digest.json" \
    --output "$TMPDIR/deferred.json" \
    --require-ready >/tmp/firstboot_handoff_index_fail.out 2>&1; then
    fail 'missing required status JSON should fail with --require-ready'
fi
assert_file_contains "$TMPDIR/deferred.json" 'missing_required_artifact:status_json'
assert_file_contains "$TMPDIR/deferred.json" '"decision": "deferred"'

assert_file_contains build_custom_iso.sh '"firstboot_release_gate_handoff_index.py"'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_handoff_index.py'
assert_file_contains docs/firstboot_release_gate_handoff_index.md 'Rollback'
assert_file_contains changelog.d/firstboot_release_gate_handoff_index.md 'firstboot_release_gate_handoff_index.py'

echo '[PASS] firstboot release-gate handoff index static coverage'
