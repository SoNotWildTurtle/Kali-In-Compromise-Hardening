# Host/VM Policy Firstboot Dry-Run Wrapper

`host_vm_policy_firstboot_dry_run.py` turns a passive Host/VM policy profile into a small bundle of aggregate review evidence. It is designed for release-gate and firstboot-review handoff before any live host or VM mutation is considered.

## Safety boundary

The wrapper is passive by design. It does not change firewall rules, services, packages, network interfaces, accounts, credentials, approval state, recovery state, IDS runtime state, models, datasets, remote-access state, or scheduled jobs.

The only permitted side effect is writing aggregate evidence files to an explicit output directory.

## Runtime output policy

By default, the wrapper writes to:

```text
/var/log/kali-hardening/host-vm-policy
```

Runtime output directories must stay under `/var/log` or `/var/lib`. Local tests can use a temporary directory only when `--allow-test-output-dir` is passed. That flag is intentionally named as a test-only override and should not be used in production firstboot packaging.

## Generated artifacts

A valid or invalid profile produces the same evidence bundle so release gates and operators can inspect failure details:

- `host_vm_policy_validator_evidence.json` — full aggregate validator evidence;
- `host_vm_policy_firstboot_manifest.json` — compact manifest tying validator evidence to the profile hash and wrapper version;
- `host_vm_policy_firstboot_handoff.json` — operator handoff index with validation status, artifact paths, safety flags, privacy boundaries, and rollback scope;
- `host_vm_policy_firstboot_evidence.md` — optional Markdown evidence when `--markdown` is supplied.

## Usage

```bash
python3 host_vm_policy_firstboot_dry_run.py profile.json
```

Write Markdown alongside JSON:

```bash
python3 host_vm_policy_firstboot_dry_run.py profile.json --markdown
```

Use a local temporary output directory during tests only:

```bash
python3 host_vm_policy_firstboot_dry_run.py profile.json \
  --output-dir /tmp/host-vm-policy-evidence \
  --allow-test-output-dir
```

## Exit codes

- `0`: profile validated and evidence was written;
- `2`: profile failed validation, but failure evidence was still written;
- `64`: nonstandard output directory was rejected;
- `74`: evidence could not be written.

## Threat-model rationale

A firstboot review gate should fail closed with machine-readable evidence rather than silently bypassing validation or requiring raw telemetry. This wrapper makes the privacy and rollback boundary explicit while reusing the existing policy validator instead of duplicating schema logic.

## Compatibility

This is an additive standard-library CLI. Existing validator commands, examples, firstboot scripts, systemd units, packaging flows, and operator workflows remain unchanged.

## Rollback

Revert `host_vm_policy_firstboot_dry_run.py`, `tests/test_host_vm_policy_firstboot_dry_run.py`, this document, and the changelog entry. No live host, VM, firewall, service, network, package, credential, account, IDS, model, dataset, recovery, approval, or scheduled-task state requires rollback.

## Follow-up work

- Add release-gate aggregation that consumes validator evidence, firstboot manifest JSON, and handoff JSON.
- Add packaging/firstboot wiring only after wrapper behavior remains green in hosted CI.
- Add operator-facing examples for default review, strict release promotion, and recovery handoff profiles.
