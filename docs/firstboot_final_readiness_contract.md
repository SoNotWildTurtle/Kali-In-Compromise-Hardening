# Firstboot final readiness contract

This document defines a passive, aggregate-only final readiness contract for firstboot release-gate handoff evidence.

## Purpose

The final readiness layer is intended to consume the existing `firstboot_release_gate.handoff_env_policy_smoke.summary.env` artifact and produce a compact go/no-go result for release review, recovery handoff, and operator dashboards.

## Required source fields

The source summary must provide quoted shell-safe values for:

- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_OK`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_DECISION`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_RELEASE_GATE`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_COMPONENT`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_DECISION`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_RELEASE_GATE`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_PRIVACY_SCOPE`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKER_COUNT`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKERS`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_TOTAL_ARTIFACTS`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_PRIVACY_SCOPE`
- `FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SAFE_DEFAULT`

## Approval rules

A final readiness helper should approve only when:

- the source smoke `OK` value is `1`;
- the source smoke decision is `approved`;
- the source smoke release gate is `pass`;
- the privacy scope is `aggregate_release_gate_handoff_env_policy_smoke_only`;
- blocker count is zero and blockers are `none` or empty;
- at least one aggregate handoff artifact is represented; and
- the safe-default text preserves a read-only contract.

Any malformed, missing, stale, privacy-mismatched, or deferred upstream evidence should fail closed with a `deferred` decision and `stop` release gate.

## Privacy and safety boundary

The final readiness layer must not read raw packets, captures, payloads, credentials, hostnames, usernames, model binaries, datasets, private logs, or live host/VM state. It should only parse the existing aggregate shell-safe summary contract and emit derived aggregate evidence.

## Rollback

Rollback is removal of the optional final readiness layer or omission from packaging/service refresh. The upstream env-policy smoke JSON, Markdown, and `.summary.env` artifacts remain authoritative.

## Follow-up implementation notes

A future helper should mirror the existing handoff readers by supporting text, JSON, Markdown, optional `.summary.env`, and `--require-pass` behavior. Static tests should cover approval, deferred evidence, malformed values, privacy-scope mismatch, packaging, firstboot service wiring, and rollback documentation.
