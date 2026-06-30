# Host/VM Policy Firstboot Dry-Run Plan

This plan defines the next safe integration step for the passive Host/VM policy validator. It intentionally remains documentation-only until a future pull request can add executable code with focused CI coverage.

## Goal

Create a firstboot-friendly dry-run wrapper that writes aggregate policy review artifacts before any live Host/VM hardening action is considered.

The wrapper should compose the existing `host_vm_policy_validator.py` behavior instead of duplicating its schema checks. It should generate:

- `host_vm_policy_validator_evidence.json`,
- `host_vm_policy_firstboot_manifest.json`,
- `host_vm_policy_firstboot_handoff.json`,
- optional operator Markdown evidence.

## Safety boundary

The dry run must be passive. It must not:

- mutate firewall, service, network interface, package, account, credential, approval, recovery, IDS runtime, model, or dataset state;
- read packet captures, raw logs, private keys, tokens, hostnames, usernames, or model binaries;
- enable persistence, scheduled jobs, remote access, blocking rules, or rollback hooks;
- infer authorization from the environment.

The only permitted side effect is writing explicitly requested aggregate evidence files under controlled output paths.

## Default output policy

Production output should stay under `/var/log` or `/var/lib` so later release gates and operator handoff tools can collect artifacts from predictable locations. Test-only output outside those prefixes should require an explicit flag and should be documented as unsuitable for production firstboot wiring.

## Required evidence fields

The handoff index should include:

- wrapper name and version,
- validator name and version,
- profile path and SHA-256,
- policy ID and mode,
- generated evidence paths,
- validation status and error count,
- required aggregate artifact names,
- passive safety flags,
- privacy-boundary booleans proving no raw telemetry or secrets are included,
- rollback scope limited to deleting generated evidence files.

## Test plan for the future code PR

A future implementation PR should add tests that verify:

1. a valid checked-in profile produces all expected aggregate JSON files;
2. invalid profiles still produce evidence and return a non-zero status;
3. nonstandard output directories are rejected unless an explicit test-only flag is used;
4. optional Markdown output contains pass/fail status and required artifacts;
5. generated handoff JSON never includes forbidden raw telemetry or secret-bearing fields;
6. documentation, changelog, and README references stay in sync.

## Rollback

Revert this planning document and its changelog/reference updates. No live host, VM, service, firewall, network, package, credential, IDS, model, dataset, recovery, approval, or scheduled state requires rollback.

## Follow-up work

- Add the standard-library firstboot dry-run wrapper as a separate focused PR.
- Add release-gate aggregation that consumes validator evidence, manifest JSON, and firstboot handoff JSON.
- Add packaging/firstboot wiring only after the dry-run interface has green static and CI coverage.
