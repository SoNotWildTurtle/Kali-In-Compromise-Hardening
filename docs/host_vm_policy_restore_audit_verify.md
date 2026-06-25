# Host/VM policy restore audit verifier

`host_vm_policy_restore_audit_verify.py` is a read-only verifier for tamper-evident JSONL audit logs produced by the manual host/VM policy restore executor.

## Purpose

The restore path already requires a restore plan, fresh approval validation, explicit manual invocation, and dry-run defaults. The audit verifier adds an independent accountability check by validating a hash chain across audit entries.

Each expected audit entry contains:

- `event_type=host_vm_policy_restore_execute`
- `previous_event_sha256`
- `event_sha256`
- restore `decision` and `mode`
- `changes_live_state`
- `requires_manual_invocation`
- plan and approval-check hashes
- target paths and action/issue counts

The verifier recomputes each entry hash after removing `event_sha256`, checks that each entry points to the previous entry, and reports tampering or chain breaks.

## Safety properties

- Does not restore files.
- Does not call service, firewall, or shell mutation helpers.
- Does not modify firewall, systemd, IDS, model, or host/VM communication policy state.
- Writes only a JSON verification result and compact report.

## Usage

Local/offline review example:

```bash
python3 host_vm_policy_restore_audit_verify.py \
  --audit-log ./policy_restore_execute.audit.jsonl \
  --output ./policy_restore_audit_verify.json \
  --report ./policy_restore_audit_verify.report
```

A valid chain returns `audit_chain_valid`. Missing, empty, malformed, tampered, or broken chains return a non-zero exit code and write issue details.

## Rationale

NIST log-management guidance emphasizes log integrity checking and protection of security logs. Recent 2025 rollback and tamper-evident logging research also supports mediated recovery with auditable, tamper-evident state transitions. This verifier keeps the current restore flow conservative while preparing the repository for append-only restore execution audit logs.

## Test coverage

`tests/test_host_vm_policy_restore_audit_verify_static.sh` builds a two-entry valid chain, verifies it, then tampers with the second entry and confirms the verifier rejects the chain.
