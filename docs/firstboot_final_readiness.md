# Firstboot final readiness helper

`firstboot_final_readiness.py` is a passive final release-gate helper for firstboot handoff evidence.

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

## Approval contract

The helper approves only when upstream smoke evidence is approved, passing, aggregate-only, blocker-free, and read-only by contract. Missing, malformed, privacy-mismatched, or deferred evidence fails closed with a `deferred` decision and `stop` release gate.

## Firstboot wiring

`firstboot_release_gate.service` refreshes JSON, Markdown, and `.summary.env` final readiness artifacts after the env-policy smoke gate runs.

## Rollback

Rollback is removal of this optional helper from packaging and firstboot service refresh. The upstream env-policy smoke JSON, Markdown, and `.summary.env` evidence remain authoritative.

## Security notes

This is a read-only aggregate helper. It does not change networking, firewall rules, host settings, VM settings, datasets, model files, approval state, restore state, credentials, or persistence. The safe default is deferred/stop when evidence is incomplete or inconsistent.
