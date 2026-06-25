#!/usr/bin/env bash
# MINC - Static-gate wrapper for safe restore executor integration fixtures.
# Defensive test only: delegates to a tempdir-based harness and never changes live /etc.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST="$ROOT_DIR/tests/test_host_vm_policy_restore_execute_integration.sh"

bash -n "$TEST"
bash "$TEST"

echo "restore executor integration fixture wrapper passed"
