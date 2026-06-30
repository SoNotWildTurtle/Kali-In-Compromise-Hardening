# Host/VM Policy Firstboot Handoff Release Gate

`host_vm_policy_firstboot_handoff_gate.py` validates the aggregate handoff JSON emitted by `host_vm_policy_firstboot_dry_run.py` before firstboot evidence is promoted into a release gate or packaging discussion.

## Safety boundary

The gate is passive and standard-library only. It reads a handoff JSON file and, optionally, checks that referenced aggregate evidence files exist. It does not read raw telemetry, secrets, private material, live service state, account data, IDS runtime data, or VM state.

## What the gate requires

A release-ready handoff must prove all of the following:

- handoff schema version is `1`;
- the producer is `host_vm_policy_firstboot_dry_run.py`;
- profile validation is green unless an operator intentionally uses `--allow-invalid-profile` for failure-review evidence;
- safety flags show passive-only behavior with no host/VM mutation, credential collection, persistence, or remote-access enablement;
- privacy flags show no raw telemetry and no secret material;
- rollback requires no live-state change;
- required aggregate artifacts are declared and, by default, exist locally.

## Usage

Validate a handoff bundle strictly:

```bash
python3 host_vm_policy_firstboot_handoff_gate.py \
  /var/log/kali-hardening/host-vm-policy/host_vm_policy_firstboot_handoff.json \
  --strict \
  --output /var/log/kali-hardening/host-vm-policy/firstboot_handoff_gate.json \
  --report /var/log/kali-hardening/host-vm-policy/firstboot_handoff_gate.report
```

Review an archived handoff where referenced files are not locally mounted:

```bash
python3 host_vm_policy_firstboot_handoff_gate.py archived_handoff.json --strict --no-require-files
```

Review invalid-profile evidence without treating `validation.valid=false` as the release blocker:

```bash
python3 host_vm_policy_firstboot_handoff_gate.py invalid_handoff.json --allow-invalid-profile
```

## Exit behavior

- Without `--strict`, the command exits `0` after writing a decision record.
- With `--strict`, `release_ready` exits `0` and `release_blocked` exits `3`.

## Threat-model rationale

The dry-run wrapper made firstboot policy evidence reviewable. This gate adds a machine-readable promotion boundary so future packaging, firstboot, or CI wiring can fail closed before any live hardening integration is considered. The checks emphasize aggregate evidence, least privilege, privacy boundaries, and reversible review-only behavior.

## Compatibility

This is additive. It does not alter existing validator commands, dry-run wrapper behavior, restore executor wiring, systemd units, packaging scripts, firstboot scripts, IDS runtime, model/data workflows, or operator workflows.

## Rollback

Revert `host_vm_policy_firstboot_handoff_gate.py`, `tests/test_host_vm_policy_firstboot_handoff_gate_static.sh`, this document, and the changelog entry. No live system state requires rollback.

## Follow-up work

- Add a dedicated hosted workflow that runs the handoff gate against a generated test bundle.
- Add packaging/firstboot wiring only after workflow coverage is green and the default bundle path is stable.
- Feed the gate decision into a broader aggregate release-readiness receipt alongside restore executor, IDS audit, and policy attestation evidence.
