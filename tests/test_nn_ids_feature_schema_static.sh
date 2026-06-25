#!/usr/bin/env bash
# MINC - Static checks for NN IDS feature schema guardrails.
# Defensive validation only: prevents feature-order and range-drift regressions.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from nn_ids_feature_schema import (
    FEATURE_NAMES,
    population_stability_index,
    validate_columns,
    validate_feature_vector,
)

expected = ["len", "ttl", "dport", "tcp_flags"]
if FEATURE_NAMES != expected:
    raise SystemExit(f"unexpected feature order: {FEATURE_NAMES}")

ok = validate_columns(["len", "ttl", "dport", "tcp_flags", "label"])
if not ok.ok:
    raise SystemExit(f"valid columns rejected: {ok.errors}")

missing = validate_columns(["len", "ttl", "dport", "label"])
if missing.ok or "tcp_flags" not in "; ".join(missing.errors):
    raise SystemExit("missing feature column was not detected")

vector = validate_feature_vector([60, 64, 443, 18])
if not vector.ok:
    raise SystemExit(f"valid vector rejected: {vector.errors}")

bad_vector = validate_feature_vector([60, 999, 443, 18])
if bad_vector.ok or "ttl" not in "; ".join(bad_vector.errors):
    raise SystemExit("invalid TTL was not detected")

psi = population_stability_index(list(range(100)), list(range(50, 150)))
if psi <= 0:
    raise SystemExit("PSI should detect shifted distributions")

print("[static-check] NN IDS feature schema checks passed")
PY
