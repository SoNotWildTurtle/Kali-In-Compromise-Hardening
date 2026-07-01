#!/usr/bin/env bash
# MINC - Static tests for the passive NN IDS triage record JSON schema.
# Defensive validation only; does not inspect live IDS, host, VM, hypervisor, packet, payload, or telemetry state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$ROOT_DIR/schemas/nn_ids_triage_record.schema.json"
VALIDATOR="$ROOT_DIR/nn_ids_triage_record_validate.sh"
DOC="$ROOT_DIR/docs/nn_ids_triage_record_validator.md"
CHANGELOG="$ROOT_DIR/changelog.d/nn_ids_triage_record_validator.md"
FIXTURE_DIR="$ROOT_DIR/examples/nn_ids_triage_records"

fail() {
  printf '[triage-schema-static][FAIL] %s\n' "$*" >&2
  exit 1
}

require_file() {
  local file="$1"
  [[ -f "$file" ]] || fail "missing required file: $file"
}

require_token() {
  local file="$1"
  local token="$2"
  grep -Fq -- "$token" "$file" || fail "$file missing required token: $token"
}

for file in "$SCHEMA" "$VALIDATOR" "$DOC" "$CHANGELOG"; do
  require_file "$file"
done

python3 - "$SCHEMA" "$VALIDATOR" "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import re
import sys

schema_path = pathlib.Path(sys.argv[1])
validator_path = pathlib.Path(sys.argv[2])
fixture_dir = pathlib.Path(sys.argv[3])

schema = json.loads(schema_path.read_text(encoding="utf-8"))
validator = validator_path.read_text(encoding="utf-8")
errors = []

required_match = re.search(r"required_keys=\(\n(?P<body>.*?)\n\)", validator, re.S)
if not required_match:
    errors.append("validator required_keys block not found")
    validator_required = []
else:
    validator_required = [line.strip() for line in required_match.group("body").splitlines() if line.strip()]

schema_required = schema.get("required", [])
if schema_required != validator_required:
    errors.append(f"schema required keys diverge from validator: {schema_required!r} != {validator_required!r}")

properties = schema.get("properties", {})
for key in validator_required:
    if key not in properties:
        errors.append(f"schema missing property for required key: {key}")

triage_enum = properties.get("triage_decision", {}).get("enum")
if triage_enum != ["pass", "watch", "degraded", "blocked"]:
    errors.append("schema triage_decision enum must match validator decisions")

if properties.get("human_review_required", {}).get("const") is not True:
    errors.append("schema must keep human_review_required const true")
if properties.get("live_action_authorized", {}).get("const") is not False:
    errors.append("schema must keep live_action_authorized const false")
if schema.get("additionalProperties") is not False:
    errors.append("schema must fail closed on additional properties")

schema_text = schema_path.read_text(encoding="utf-8")
for token in [
    "aggregate-only; no raw telemetry or secrets",
    "passive evidence only",
    "human_review_required=true",
    "live_action_authorized=false",
    "no operational commands",
    "release_gate_contract",
]:
    if token not in schema_text:
        errors.append(f"schema missing safety token: {token}")

fixtures = sorted(fixture_dir.glob("*.env"))
if not fixtures:
    errors.append("no triage fixtures found")

for fixture in fixtures:
    record = {}
    for raw_line in fixture.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            errors.append(f"{fixture.name}: malformed fixture line for schema parity: {line}")
            continue
        key, value = line.split("=", 1)
        record[key] = value

    missing = [key for key in schema_required if key not in record]
    extra = sorted(set(record) - set(schema_required))
    if missing:
        errors.append(f"{fixture.name}: missing schema keys {missing}")
    if extra:
        errors.append(f"{fixture.name}: contains keys outside schema {extra}")
    if record.get("triage_decision") not in triage_enum:
        errors.append(f"{fixture.name}: unsupported triage_decision {record.get('triage_decision')!r}")
    if record.get("human_review_required") != "true":
        errors.append(f"{fixture.name}: must keep human_review_required=true")
    if record.get("live_action_authorized") != "false":
        errors.append(f"{fixture.name}: must keep live_action_authorized=false")
    if "aggregate-only; no raw telemetry or secrets" not in record.get("privacy_scope", ""):
        errors.append(f"{fixture.name}: privacy_scope must stay aggregate-only and secret-free")
    if "estimate" not in record.get("uncertainty_note", "") and "uncertainty" not in record.get("uncertainty_note", ""):
        errors.append(f"{fixture.name}: uncertainty_note must mention estimate or uncertainty")

if errors:
    for error in errors:
        print(f"[triage-schema-static][FAIL] {error}", file=sys.stderr)
    sys.exit(1)

print("[triage-schema-static] JSON schema parity checks passed")
PY

for token in \
  'schemas/nn_ids_triage_record.schema.json' \
  'JSON schema' \
  'machine-readable' \
  'release_gate_contract'; do
  require_token "$DOC" "$token"
  require_token "$CHANGELOG" "$token"
done

printf '[triage-schema-static] NN IDS triage record schema checks passed\n'
