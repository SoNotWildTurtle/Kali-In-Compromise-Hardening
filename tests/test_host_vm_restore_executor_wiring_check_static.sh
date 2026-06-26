#!/usr/bin/env bash
# MINC - Static tests for the manual restore executor wiring release check.
# Defensive test only: uses temporary fixture repositories and never changes live host/VM state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_restore_executor_wiring_check.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"

python3 - "$SCRIPT" <<'PY'
import ast
import sys
from pathlib import Path

module = ast.parse(Path(sys.argv[1]).read_text(encoding="utf-8"))
for node in ast.walk(module):
    if isinstance(node, ast.Dict):
        keys = [item.value for item in node.keys if isinstance(item, ast.Constant)]
        values = node.values
        if "changes_live_state" in keys:
            value = values[keys.index("changes_live_state")]
            assert isinstance(value, ast.Constant) and value.value is False
            break
else:
    raise AssertionError("changes_live_state must be declared as a static False value")
PY
grep -q "host_vm_policy_restore_execute.timer" "$SCRIPT"
grep -q "ProtectSystem=strict" "$SCRIPT"

mkdir -p "$TMPDIR/fixture/tests" "$TMPDIR/fixture/docs"
cat > "$TMPDIR/fixture/build_custom_iso.sh" <<'EOF_BUILD'
core_modules=(
    "host_vm_policy_restore_execute.py"
    "host_vm_policy_restore_execute.service"
)
EOF_BUILD
cat > "$TMPDIR/fixture/firstboot.sh" <<'EOF_FIRSTBOOT'
#!/usr/bin/env bash
# restore executor is manual only; no timer reference here.
EOF_FIRSTBOOT
cat > "$TMPDIR/fixture/vm_smoke_check.sh" <<'EOF_SMOKE'
/usr/local/bin/host_vm_policy_restore_execute.py
host_vm_policy_restore_execute.service
/var/lib/host_vm_comm_guard/policy_restore_execute.json
/var/log/host_vm_policy_restore_execute.report
EOF_SMOKE
cat > "$TMPDIR/fixture/tests/run_static_security_checks.sh" <<'EOF_STATIC'
host_vm_policy_restore_execute.py
host_vm_policy_restore_execute.service
test_*_static.sh
EOF_STATIC
cat > "$TMPDIR/fixture/host_vm_policy_restore_execute.service" <<'EOF_SERVICE'
ConditionPathExists=/var/lib/host_vm_comm_guard/policy_restore_approval_check.json
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_UNIX
MemoryDenyWriteExecute=true
EOF_SERVICE
cat > "$TMPDIR/fixture/docs/host_vm_policy_restore_execute.md" <<'EOF_DOC'
The manual restore executor defaults to dry-run. Use --execute only after approval_valid and manual_restore_review_required. It deliberately does not run from a timer.
EOF_DOC
: > "$TMPDIR/fixture/host_vm_policy_restore_execute.py"
: > "$TMPDIR/fixture/tests/test_host_vm_policy_restore_execute_static.sh"

python3 "$SCRIPT" --root "$TMPDIR/fixture" --strict --output "$TMPDIR/release_ready.json" --report "$TMPDIR/report.txt" >/dev/null
python3 - "$TMPDIR/release_ready.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
assert result["decision"] == "release_ready", result
assert result["checks_failed"] == 0, result
assert result["changes_live_state"] is False, result
PY

cp -a "$TMPDIR/fixture" "$TMPDIR/fixture_missing_iso"
python3 - "$TMPDIR/fixture_missing_iso/build_custom_iso.sh" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text().replace('    "host_vm_policy_restore_execute.py"\n', ''))
PY
if python3 "$SCRIPT" --root "$TMPDIR/fixture_missing_iso" --strict --output "$TMPDIR/missing_iso.json" >/dev/null 2>&1; then
    echo "wiring checker should fail strict mode when ISO packaging is incomplete" >&2
    exit 1
fi
python3 - "$TMPDIR/missing_iso.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
assert result["decision"] == "wiring_review_required", result
assert result["checks_failed"] >= 1, result
PY

cp -a "$TMPDIR/fixture" "$TMPDIR/fixture_timer"
: > "$TMPDIR/fixture_timer/host_vm_policy_restore_execute.timer"
if python3 "$SCRIPT" --root "$TMPDIR/fixture_timer" --strict >/dev/null 2>&1; then
    echo "wiring checker should reject timer-driven restore execution" >&2
    exit 1
fi

echo "host_vm_restore_executor_wiring_check static tests passed"
