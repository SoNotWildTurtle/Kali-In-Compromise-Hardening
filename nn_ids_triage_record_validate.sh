#!/usr/bin/env bash
# MINC - Dependency-free passive NN IDS triage record validator.
# Defensive validation only; does not inspect live IDS, host, VM, hypervisor, packet, payload, or telemetry state.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: nn_ids_triage_record_validate.sh [--release-gate] [--emit-json] <triage-record>
       nn_ids_triage_record_validate.sh --print-template

Validates a passive aggregate-only NN IDS triage record written as stable key=value
lines. By default the validator checks record shape and safety boundaries for all
supported decisions. With --release-gate, only pass/watch records with safe release
handoff metadata are accepted for promotion evidence.

Use --print-template to write a conservative key=value template to stdout for
reviewers who need a reproducible starting point. Use --emit-json to write the
validated record as schema-compatible JSON for release receipts or handoff
bundles.

This tool is intentionally passive. It reads one local text file and does not run
live IDS checks, inspect packets, mutate services, change firewall policy, retrain
models, execute restores, or contact host/VM/hypervisor APIs.
EOF
}

print_template() {
  cat <<'EOF'
# Passive NN IDS triage record template.
# Fill every value with aggregate-only evidence. Do not include raw telemetry,
# secrets, packet captures, payloads, endpoint identifiers, or operational commands.
triage_decision=watch
release_ready=false
source_artifacts=nn_ids_release_readiness_summary.json,nn_ids_health_evidence.json,nn_ids_drift_evidence.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none; replace with concise blocker summary if degraded or blocked
uncertainty_note=aggregate evidence is an analytical estimate that requires human review before promotion
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=confirm hosted release gates, freshness, drift, and model-card evidence before merge
owner=release-reviewer
EOF
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\t'/\\t}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

emit_json_record() {
  local key
  local value
  local comma=""
  printf '{\n'
  for key in "${required_keys[@]}"; do
    printf '%s  "%s": ' "$comma" "$key"
    case "$key" in
      release_ready|human_review_required|live_action_authorized)
        printf '%s' "${fields[$key]}"
        ;;
      *)
        value="$(json_escape "${fields[$key]}")"
        printf '"%s"' "$value"
        ;;
    esac
    comma=$',\n'
  done
  printf '\n}\n'
}

release_gate=false
emit_json=false
record_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-gate)
      release_gate=true
      shift
      ;;
    --emit-json)
      emit_json=true
      shift
      ;;
    --print-template)
      if [[ "$release_gate" == true || "$emit_json" == true || -n "$record_path" || $# -ne 1 ]]; then
        printf '[triage-record-validator][FAIL] --print-template cannot be combined with --release-gate, --emit-json, a record path, or other options\n' >&2
        usage >&2
        exit 2
      fi
      print_template
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      printf '[triage-record-validator][FAIL] unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$record_path" ]]; then
        printf '[triage-record-validator][FAIL] only one triage record may be supplied\n' >&2
        usage >&2
        exit 2
      fi
      record_path="$1"
      shift
      ;;
  esac
done

if [[ -z "$record_path" ]]; then
  printf '[triage-record-validator][FAIL] missing triage record path\n' >&2
  usage >&2
  exit 2
fi

if [[ ! -f "$record_path" ]]; then
  printf '[triage-record-validator][FAIL] missing triage record: %s\n' "$record_path" >&2
  exit 1
fi

failures=0
fail() {
  printf '[triage-record-validator][FAIL] %s\n' "$*" >&2
  failures=$((failures + 1))
}

# Reject common attempts to make a passive record executable or operational.
if grep -Eq '(^|[[:space:]])(sudo|curl|wget|nc|ncat|bash -c|python3? -c|systemctl|iptables|nft|ssh|scp|rsync|restore|retrain|autoblock|scan)[[:space:]]' "$record_path"; then
  fail 'record contains operational command-like text; keep triage records passive evidence only'
fi

if grep -Eq '(BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{30,}|xox[baprs]-)' "$record_path"; then
  fail 'record appears to contain a private key or access token pattern'
fi

declare -A fields=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  if [[ ! "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
    fail "malformed non-empty line: $line"
    continue
  fi
  key="${line%%=*}"
  value="${line#*=}"
  if [[ -n "${fields[$key]+set}" ]]; then
    fail "duplicate key: $key"
  fi
  fields[$key]="$value"
done < "$record_path"

required_keys=(
  triage_decision
  release_ready
  source_artifacts
  artifact_hashes
  blocking_issues
  uncertainty_note
  privacy_scope
  human_review_required
  live_action_authorized
  rollback_reference
  next_evidence_needed
  owner
)

for key in "${required_keys[@]}"; do
  if [[ -z "${fields[$key]+set}" ]]; then
    fail "missing required key: $key"
  elif [[ -z "${fields[$key]}" ]]; then
    fail "empty required key: $key"
  fi
done

triage_decision="${fields[triage_decision]:-}"
case "$triage_decision" in
  pass|watch|degraded|blocked) ;;
  *) fail "unsupported triage_decision: ${triage_decision:-<missing>}" ;;
esac

case "${fields[release_ready]:-}" in
  true|false) ;;
  *) fail 'release_ready must be true or false' ;;
esac

[[ "${fields[human_review_required]:-}" == "true" ]] || fail 'human_review_required must be true'
[[ "${fields[live_action_authorized]:-}" == "false" ]] || fail 'live_action_authorized must be false'

privacy_scope="${fields[privacy_scope]:-}"
[[ "$privacy_scope" == *aggregate-only* ]] || fail 'privacy_scope must explicitly include aggregate-only'
[[ "$privacy_scope" == *'no raw telemetry or secrets'* ]] || fail 'privacy_scope must explicitly reject raw telemetry and secrets'

for unsafe_key in packet_capture pcap payload raw_telemetry credential secret endpoint_identifier host_identifier vm_identifier; do
  if [[ -n "${fields[$unsafe_key]+set}" ]]; then
    fail "record must not include unsafe raw-data key: $unsafe_key"
  fi
done

[[ "${fields[uncertainty_note]:-}" == *estimate* || "${fields[uncertainty_note]:-}" == *uncertainty* ]] || \
  fail 'uncertainty_note must explain uncertainty or estimate limits'

[[ "${fields[rollback_reference]:-}" == docs/* || "${fields[rollback_reference]:-}" == *rollback* ]] || \
  fail 'rollback_reference must point to rollback guidance'

[[ "${fields[source_artifacts]:-}" == *nn_ids_* ]] || fail 'source_artifacts must reference NN IDS aggregate evidence'
[[ "${fields[artifact_hashes]:-}" == *sha256* || "${fields[artifact_hashes]:-}" == manifest:* ]] || \
  fail 'artifact_hashes must include sha256 evidence or a manifest reference'

if [[ "$release_gate" == true ]]; then
  case "$triage_decision" in
    pass|watch) ;;
    degraded|blocked) fail "release gate rejects triage_decision=$triage_decision" ;;
  esac
  [[ "${fields[release_ready]:-}" == "true" ]] || fail 'release gate requires release_ready=true'
  [[ "${fields[blocking_issues]:-}" == none* ]] || fail 'release gate requires blocking_issues=none or none-prefixed follow-up text'
fi

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi

if [[ "$emit_json" == true ]]; then
  emit_json_record
  exit 0
fi

printf '[triage-record-validator] %s accepted for passive validation' "$record_path"
if [[ "$release_gate" == true ]]; then
  printf ' and release-gate evidence'
fi
printf '\n'
