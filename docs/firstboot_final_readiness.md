# Firstboot final readiness helper

`firstboot_final_readiness.py` is a passive final release-gate helper for firstboot handoff evidence.

This firstboot final readiness helper keeps downstream release review on an aggregate-only, read-only evidence contract.

## Purpose

The helper consumes only the aggregate shell-safe summary emitted by `firstboot_release_gate_handoff_env_policy_smoke.py` and derives a compact final readiness result for release review, recovery handoff, and operator dashboards.

It does not inspect raw packets, captures, payloads, credentials, hostnames, usernames, model binaries, datasets, private logs, or live host/VM state.

## Inputs

Default input:

- `/var/log/firstboot_release_gate.handoff_env_policy_smoke.summary.env`

The input must contain quoted `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_*` fields for upstream decision, release gate, blocker count, blocker list, artifact count, privacy scope, and safe-default evidence.

## Outputs

The helper can emit:

- text status for operators;
- JSON evidence for machine-readable release gates;
- Markdown evidence for handoff packets; and
- optional `.summary.env` sidecar values under the `FIRSTBOOT_FINAL_READINESS_*` prefix.

## Smoke validation

`firstboot_final_readiness_smoke.py` is an additive passive smoke gate for the final-readiness `.summary.env` sidecar. It parses the quoted `FIRSTBOOT_FINAL_READINESS_*` contract without sourcing it, confirms the final helper stayed aggregate-only and read-only, verifies approved/pass/deferred/stop consistency, checks blocker and artifact counts, and emits JSON, Markdown, and optional `FIRSTBOOT_FINAL_READINESS_SMOKE_*` summary evidence.

The smoke helper fails closed when the summary is missing, malformed, privacy-scope mismatched, marked pass while failed, missing blocker details, missing artifact counts, or inconsistent with the final-readiness component identity. It exists so release jobs, firstboot dashboards, and recovery handoff tooling can consume a stable sidecar contract before trusting the final aggregate readiness result.

## Manifest handoff

`firstboot_final_readiness_manifest.py` is an additive passive manifest helper for the final-readiness smoke `.summary.env` sidecar. It parses the quoted `FIRSTBOOT_FINAL_READINESS_SMOKE_*` contract without sourcing it, verifies approved/pass/deferred/stop consistency, confirms aggregate-only privacy scope, checks blocker and artifact counts, and emits JSON, Markdown, and optional `FIRSTBOOT_FINAL_READINESS_MANIFEST_*` summary evidence.

The manifest helper records the expected firstboot release-gate artifact set for review and recovery handoff:

- `/var/log/firstboot_release_gate.json`
- `/var/log/firstboot_release_gate.md`
- `/var/log/firstboot_release_gate.summary.env`
- `/var/log/firstboot_release_gate.final_readiness.json`
- `/var/log/firstboot_release_gate.final_readiness.md`
- `/var/log/firstboot_release_gate.final_readiness.summary.env`
- `/var/log/firstboot_release_gate.final_readiness_smoke.json`
- `/var/log/firstboot_release_gate.final_readiness_smoke.md`
- `/var/log/firstboot_release_gate.final_readiness_smoke.summary.env`

It does not hash, read, or embed those artifacts directly. It keeps the manifest aggregate-only so downstream dashboards and release gates can check completeness without exposing raw telemetry or sensitive environment details.

## Approval contract

The helper approves only when upstream smoke evidence is approved, passing, aggregate-only, blocker-free, and read-only by contract. Missing, malformed, privacy-mismatched, or deferred evidence fails closed with a `deferred` decision and `stop` release gate.

The smoke helper approves only when the final-readiness summary itself is approved, passing, aggregate-only, blocker-free, backed by at least one upstream artifact, and internally consistent. It does not promote, merge, approve restore execution, change system state, or override the underlying final-readiness decision.

The manifest helper approves only when final-readiness smoke evidence is approved, passing, aggregate-only, blocker-free, read-only by contract, and backed by at least one upstream artifact. Missing, malformed, privacy-mismatched, blocker-inconsistent, or artifact-empty evidence fails closed with `deferred` and `stop`.

## Firstboot wiring

`firstboot_release_gate.service` refreshes JSON, Markdown, and `.summary.env` final readiness artifacts after the env-policy smoke gate runs.

The same service then refreshes final-readiness smoke JSON, Markdown, and `.summary.env` artifacts:

- `/var/log/firstboot_release_gate.final_readiness_smoke.json`
- `/var/log/firstboot_release_gate.final_readiness_smoke.md`
- `/var/log/firstboot_release_gate.final_readiness_smoke.summary.env`

The service now also refreshes final-readiness manifest JSON, Markdown, and `.summary.env` artifacts:

- `/var/log/firstboot_release_gate.final_readiness_manifest.json`
- `/var/log/firstboot_release_gate.final_readiness_manifest.md`
- `/var/log/firstboot_release_gate.final_readiness_manifest.summary.env`

## Rollback

Rollback is removal of this optional helper from packaging and firstboot service refresh. The upstream env-policy smoke JSON, Markdown, and `.summary.env` evidence remain authoritative.

Rollback for the smoke helper is removal of `firstboot_final_readiness_smoke.py` from packaging and removal of the final-readiness smoke `ExecStartPost=` lines from `firstboot_release_gate.service`. The final-readiness JSON, Markdown, and `.summary.env` artifacts remain authoritative.

Rollback for the manifest helper is removal of `firstboot_final_readiness_manifest.py` from packaging and removal of the final-readiness manifest `ExecStartPost=` lines from `firstboot_release_gate.service`. The final-readiness and final-readiness smoke JSON, Markdown, and `.summary.env` artifacts remain authoritative.

## Security notes

This is a read-only aggregate helper. It does not change networking, firewall rules, host settings, VM settings, datasets, model files, approval state, restore state, credentials, or persistence. The safe default is deferred/stop when evidence is incomplete or inconsistent.

The smoke helper is also read-only and aggregate-only. It does not source shell content, open sockets, inspect raw telemetry, read model binaries, mutate `/var/log` inputs, alter services, change firewall state, approve restores, or modify host/VM settings. Its safe default is deferred/stop when the final-readiness sidecar is incomplete, malformed, privacy-mismatched, or internally inconsistent.

The manifest helper is read-only and aggregate-only. It does not source shell content, open sockets, inspect raw telemetry, read model binaries, mutate `/var/log` inputs, alter services, change firewall state, approve restores, modify host/VM settings, or embed sensitive environment data. Its safe default is deferred/stop when the final-readiness smoke sidecar is incomplete, malformed, privacy-mismatched, blocker-inconsistent, or artifact-empty.
