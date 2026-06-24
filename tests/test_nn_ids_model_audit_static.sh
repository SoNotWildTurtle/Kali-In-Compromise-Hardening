#!/usr/bin/env bash
# MINC - Static validation for the defensive NN IDS model audit module.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/nn_ids_model_audit.py"
SERVICE="$ROOT_DIR/nn_ids_model_audit.service"
TIMER="$ROOT_DIR/nn_ids_model_audit.timer"
DOC="$ROOT_DIR/docs/nn_ids_model_audit.md"
BUILD="$ROOT_DIR/build_custom_iso.sh"
FIRSTBOOT="$ROOT_DIR/firstboot.sh"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

[[ -f "$SCRIPT" ]] || fail "missing nn_ids_model_audit.py"
[[ -f "$SERVICE" ]] || fail "missing nn_ids_model_audit.service"
[[ -f "$TIMER" ]] || fail "missing nn_ids_model_audit.timer"
[[ -f "$DOC" ]] || fail "missing docs/nn_ids_model_audit.md"

python3 -m py_compile "$SCRIPT"

grep -q 'balanced_accuracy_score' "$SCRIPT" || fail "balanced accuracy metric missing"
grep -q 'permutation_importance' "$SCRIPT" || fail "feature importance audit missing"
grep -q 'robustness_index' "$SCRIPT" || fail "robustness index missing"
grep -q 'baseline_feature_stats' "$SCRIPT" || fail "drift baseline missing"
grep -q 'NoNewPrivileges=true' "$SERVICE" || fail "service hardening missing"
grep -q 'Persistent=true' "$TIMER" || fail "timer persistence missing"
grep -q 'nn_ids_model_audit.py' "$BUILD" || fail "ISO packaging hook missing"
grep -q 'nn_ids_model_audit.timer' "$FIRSTBOOT" || fail "firstboot timer hook missing"
grep -q 'concept drift' "$DOC" || fail "research rationale missing from docs"

echo "nn_ids_model_audit static validation passed"
