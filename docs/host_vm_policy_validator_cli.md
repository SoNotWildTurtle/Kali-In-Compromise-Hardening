# Host/VM Policy Validator CLI

`host_vm_policy_validator.py` validates a Host/VM policy configuration profile against the repository's passive policy-review contract and emits review evidence without changing live host or VM state.

The validator is intentionally offline and standard-library only. It is suitable for local review, recovery handoff, firstboot release-gate dry runs, and CI smoke validation where installing extra packages is undesirable.

## Safety model

The CLI:

- reads one JSON profile supplied by the operator,
- checks defensive-use acknowledgement, aggregate-only privacy boundaries, bounded freshness values, aggregate artifact paths, and file-only rollback notes,
- emits JSON or Markdown evidence,
- returns `0` for valid profiles and `2` for invalid profiles,
- does not mutate host or VM state,
- does not read raw logs, packets, captures, datasets, secrets, hostnames, usernames, credentials, private keys, tokens, model binaries, firewall rules, network interfaces, service state, approval state, or restore state.

## Example profile

Create `examples/host_vm_policy_default_review.json` or another local profile using the schema documented in `docs/host_vm_policy_configuration_schema.md`.

## JSON evidence

```bash
python3 host_vm_policy_validator.py examples/host_vm_policy_default_review.json
```

Expected successful output includes:

```json
{
  "valid": true,
  "safety": {
    "passive_only": true,
    "mutates_host_or_vm_state": false,
    "reads_raw_telemetry": false,
    "emits_aggregate_review_evidence": true
  }
}
```

## Markdown evidence

```bash
python3 host_vm_policy_validator.py examples/host_vm_policy_default_review.json --format markdown --output /tmp/host_vm_policy_validation.md
```

Markdown output is intended for operator handoff notes or pull-request evidence. It summarizes pass/fail status, policy identity, mode, passive-only status, aggregate-only status, validation errors, and required aggregate artifacts.

## Validation coverage

Run the focused regression suite with:

```bash
python3 -m pytest tests/test_host_vm_policy_validator_cli.py
```

The tests cover:

- a valid policy profile,
- unsafe remote host mutation and privacy-boundary failures,
- Markdown output and file writing,
- documentation and changelog traceability.

## Compatibility

The CLI uses only Python's standard library and does not require `jsonschema` or network access. It can coexist with future JSON Schema validators because it enforces the same repository-level policy expectations rather than replacing the schema.

## Rollback

Delete these files:

- `host_vm_policy_validator.py`
- `docs/host_vm_policy_validator_cli.md`
- `docs/changelog_host_vm_policy_validator_cli.md`
- `tests/test_host_vm_policy_validator_cli.py`

No service, timer, firstboot hook, firewall rule, network interface, package, approval state, restore state, IDS model, dataset, credential, account, host state, or VM state requires rollback.

## Follow-up work

- Add example profiles for default review, strict release promotion, and recovery handoff.
- Add an optional firstboot dry-run wrapper that writes validator output under `/var/log` only after static and CI coverage exists.
- Add release-gate aggregation that consumes validator JSON while preserving aggregate-only privacy boundaries.
