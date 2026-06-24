#!/usr/bin/env bash
# MINC - Static validation for host_vm_comm_guard.sh.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_comm_guard.sh"
SERVICE="$ROOT_DIR/host_vm_comm_guard.service"
DOC="$ROOT_DIR/docs/host_vm_comm_guard.md"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

[[ -f "$SCRIPT" ]] || fail "missing host_vm_comm_guard.sh"
[[ -f "$SERVICE" ]] || fail "missing host_vm_comm_guard.service"
[[ -f "$DOC" ]] || fail "missing docs/host_vm_comm_guard.md"

bash -n "$SCRIPT"

grep -q 'table inet host_vm_comm_guard' "$SCRIPT" || fail "nftables table name missing"
grep -q 'nft -c -f' "$SCRIPT" || fail "nftables syntax check missing"
grep -q 'HOST_VM_HOST_CIDR' "$SCRIPT" || fail "host CIDR config missing"
grep -q 'ExecStart=/usr/local/bin/host_vm_comm_guard.sh apply' "$SERVICE" || fail "service apply command missing"
grep -q 'ExecStop=/usr/local/bin/host_vm_comm_guard.sh remove' "$SERVICE" || fail "service remove command missing"
grep -q 'IDS integration path' "$DOC" || fail "IDS documentation hook missing"

echo "host_vm_comm_guard static validation passed"
