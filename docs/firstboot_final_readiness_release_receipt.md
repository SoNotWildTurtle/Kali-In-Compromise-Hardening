# Firstboot final readiness release receipt

`firstboot_final_readiness_release_receipt.py` is a passive release-review helper that turns the operator-bundle index into a concise approved/deferred receipt. It is intended for final image promotion, recovery handoff, and operator review after the firstboot release-gate evidence chain has already produced aggregate JSON, Markdown, and summary artifacts.

## Generated artifacts

The firstboot release-gate service refreshes these review artifacts:

- `/var/log/firstboot_release_gate.final_readiness_release_receipt.json`
- `/var/log/firstboot_release_gate.final_readiness_release_receipt.md`
- `/var/log/firstboot_release_gate.final_readiness_release_receipt.summary.env`

The JSON output is the stable machine-readable contract. The Markdown output is for human review. The `.summary.env` sidecar is shell-friendly but should be parsed as quoted aggregate evidence, not sourced as executable shell.

## Decision contract

A receipt is `approved` only when the operator-bundle index is passing, upstream operator-bundle smoke evidence is passing, and the indexed firstboot evidence inventory contains no missing or zero-byte artifacts. Any missing input, malformed JSON, deferred upstream status, missing artifact, or zero-byte artifact produces a `deferred` receipt with blockers.

This gives release gates and recovery handoffs an explicit stop condition without attempting automatic repair.

## Threat-model rationale

The helper is intentionally passive and aggregate-only. It reads the operator-bundle index JSON and writes derived receipt artifacts. It does not source shell content, inspect raw telemetry, open sockets, modify firewall rules, mutate services, approve restores, start persistence, change model files, update datasets, or alter host/VM state.

The receipt excludes raw logs, packet captures, hostnames, usernames, credentials, secrets, model binaries, datasets, environment identifiers, and raw IDS telemetry.

## Compatibility

The helper uses only Python standard-library modules. It is additive to the existing firstboot release-gate service and does not remove any earlier evidence artifact, helper, CLI option, systemd hardening setting, or user workflow.

## Rollback

Rollback is safe and reversible:

1. Remove `firstboot_final_readiness_release_receipt.py` from `build_custom_iso.sh`.
2. Remove the two release receipt `ExecStartPost=` lines from `firstboot_release_gate.service`.
3. Delete generated `/var/log/firstboot_release_gate.final_readiness_release_receipt.*` artifacts.

No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.

## Follow-up work

- Feed the receipt into an optional operator dashboard after the JSON contract settles.
- Add CI release gates that invoke `--require-approved` against captured fixture evidence.
- Add an age/freshness threshold for the receipt after the upstream artifact-age contracts stabilize.
