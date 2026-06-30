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

## Release receipt

`host_vm_policy_firstboot_release_receipt.py` consumes `firstboot_handoff_gate.json` and writes a compact `firstboot_release_receipt.json` plus optional text report. It is a second passive promotion boundary for CI artifacts and later aggregate release gates.

```bash
python3 host_vm_policy_firstboot_release_receipt.py \
  /var/log/kali-hardening/host-vm-policy/firstboot_handoff_gate.json \
  --strict \
  --output /var/log/kali-hardening/host-vm-policy/firstboot_release_receipt.json \
  --report /var/log/kali-hardening/host-vm-policy/firstboot_release_receipt.report
```

A strict receipt requires the source gate to be `release_ready`, report zero failed checks, keep `changes_live_state=false`, and keep `reads_raw_telemetry=false`. The receipt exits non-zero when the source gate is blocked, malformed, or not from `host_vm_policy_firstboot_handoff_gate.py`.

See `docs/firstboot_release_receipt_blocked_examples.md` for expected blocked receipt behavior, including normal blocked gate evidence versus malformed evidence. Blocked examples are intentionally synthetic and aggregate-only so reviewers can validate fail-closed behavior without mutating host or VM state.

## Hosted workflow

`.github/workflows/firstboot-handoff-release-gate.yml` runs the module static tests, builds synthetic aggregate handoff evidence on the hosted runner, evaluates it with `--strict`, creates the release receipt, verifies the `release_ready` and `release_receipt_ready` JSON/report decisions, and uploads only aggregate handoff gate and receipt evidence.

The workflow also builds an expected-blocked synthetic fixture with `validation.valid=false`, evaluates it without `--strict`, verifies the blocked gate and receipt decisions, and uploads those expected-negative aggregate artifacts under `firstboot-handoff-gate-blocked-fixture`. This lets reviewers compare ready evidence with intentionally blocked evidence without weakening the primary release gate or making expected-negative fixtures fail CI.

The workflow is intentionally passive. It does not install packages, start services, change firewall rules, touch host or VM state, collect credentials, read raw telemetry, or fetch external data.

## Exit behavior

- Without `--strict`, the handoff gate exits `0` after writing a decision record.
- With `--strict`, handoff gate `release_ready` exits `0` and `release_blocked` exits `3`.
- With `--strict`, release receipt `release_receipt_ready` exits `0` and `release_receipt_blocked` exits `4`.

## Threat-model rationale

The dry-run wrapper made firstboot policy evidence reviewable. This gate and receipt pair add a machine-readable promotion boundary so future packaging, firstboot, or CI wiring can fail closed before any live hardening integration is considered. The checks emphasize aggregate evidence, least privilege, privacy boundaries, and reversible review-only behavior.

## Compatibility

This is additive. It does not alter existing validator commands, dry-run wrapper behavior, restore executor wiring, systemd units, packaging scripts, firstboot scripts, IDS runtime, model/data workflows, or operator workflows.

## Rollback

Revert `host_vm_policy_firstboot_handoff_gate.py`, `host_vm_policy_firstboot_release_receipt.py`, their static tests, this document, the workflow, workflow static test, and the changelog entries. No live system state requires rollback.

## Follow-up work

- Feed the firstboot release receipt into a broader aggregate release-readiness receipt alongside restore executor, IDS audit, and policy attestation evidence.
- Add packaging/firstboot wiring only after repeated workflow coverage is green and the default bundle path is stable.
- Promote the blocked-fixture artifact into a broader release-readiness summary once restore executor and IDS aggregate evidence use the same expected-negative pattern.
