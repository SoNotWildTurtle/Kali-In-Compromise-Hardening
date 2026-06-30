# Host/VM Policy Configuration Schema

This document introduces a passive schema for host/VM policy configuration review. It is designed for future firstboot and release-gate workflows that need a predictable contract for artifact freshness, authorization defaults, evidence paths, privacy boundaries, and rollback notes before any host/VM isolation change is promoted.

The companion JSON Schema is `docs/host_vm_policy_configuration_schema.json`.

## Purpose

The host/VM policy and firstboot handoff helpers already produce privacy-safe aggregate evidence. A configuration schema gives reviewers a stable way to validate the policy settings that control those helpers before a release, without reading raw telemetry or changing the live system.

The schema is intentionally additive and passive. It does not change host state, VM state, firewall rules, network interfaces, services, approval state, restore state, IDS models, datasets, accounts, credentials, or firstboot behavior.

## Configuration contract

A valid policy configuration must declare:

- `schema_version`: currently `1`.
- `policy_id`: a stable lowercase identifier for the reviewed policy profile.
- `mode`: one of `passive_review`, `firstboot_release_gate`, or `operator_handoff`.
- `authorization`: defensive-use flags that require explicit operator acknowledgement and keep remote host mutation disabled by default.
- `freshness`: optional artifact-age policy with a bounded maximum age and a bounded future timestamp tolerance.
- `artifacts`: expected aggregate evidence paths under `/var/log` or `/var/lib`.
- `privacy_boundaries`: aggregate-only evidence with forbidden raw telemetry and secret fields.
- `rollback`: confirmation that rollback is limited to reverting schema/configuration files and does not require live-state mutation.

## Example profile

```json
{
  "schema_version": 1,
  "policy_id": "default_firstboot_review",
  "mode": "firstboot_release_gate",
  "authorization": {
    "authorized_defensive_use_only": true,
    "operator_acknowledgement_required": true,
    "remote_host_mutation_allowed": false
  },
  "freshness": {
    "enabled": true,
    "max_artifact_age_minutes": 1440,
    "future_clock_skew_tolerance_seconds": 300
  },
  "artifacts": [
    {
      "name": "firstboot_handoff_index_json",
      "path": "/var/log/host_vm_policy_firstboot_handoff.json",
      "required": true,
      "producer": "host_vm_policy_firstboot_handoff.py"
    },
    {
      "name": "firstboot_manifest_json",
      "path": "/var/log/host_vm_policy_firstboot_manifest.json",
      "required": true,
      "producer": "host_vm_policy_firstboot_manifest.py"
    }
  ],
  "privacy_boundaries": {
    "aggregate_only": true,
    "forbidden_fields": [
      "raw_logs",
      "packets",
      "captures",
      "credentials",
      "hostnames",
      "usernames",
      "secrets",
      "datasets"
    ]
  },
  "rollback": {
    "revert_files_only": true,
    "live_state_rollback_required": false,
    "notes": "Revert the schema/configuration increment only; existing host, VM, firewall, service, IDS, restore, model, dataset, credential, and account state remains unchanged."
  }
}
```

## Review guidance

Use the schema as a release-review contract before wiring any future policy profile into firstboot packaging. A reviewer should confirm that:

1. The profile is explicitly defensive and requires operator acknowledgement.
2. `remote_host_mutation_allowed` remains `false` for passive release-gate review.
3. Artifact paths point only to aggregate evidence under `/var/log` or `/var/lib`.
4. Freshness thresholds are bounded and suitable for the handoff window.
5. Privacy boundaries exclude raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, datasets, private keys, and tokens.
6. Rollback remains file-only and does not loosen host/VM isolation or security controls.

## Threat-model rationale

The schema makes policy intent explicit before automation consumes a configuration. That reduces accidental promotion of stale evidence, raw telemetry leakage, or unsafe host/VM mutation assumptions while preserving least privilege and operator review.

## Compatibility

This increment does not require a new dependency. The JSON Schema is a documented contract for future validators and can be checked by tools that already support JSON Schema draft 2020-12. Existing scripts and user workflows continue to work unchanged.

## Rollback

Rollback requires deleting `docs/host_vm_policy_configuration_schema.json`, `docs/host_vm_policy_configuration_schema.md`, `docs/changelog_host_vm_policy_configuration_schema.md`, and `tests/test_host_vm_policy_configuration_schema.py`. No live host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, account, or package state requires rollback.

## Follow-up work

- Add an offline validator CLI that accepts a policy profile and emits JSON/Markdown review evidence.
- Wire the validator into firstboot release-gate review only after tests cover passing, malformed, stale, and privacy-unsafe profiles.
- Add example profiles for default review, strict release promotion, and recovery handoff.
