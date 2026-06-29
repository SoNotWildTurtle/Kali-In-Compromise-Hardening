# Firstboot final readiness operator bundle index

`firstboot_final_readiness_operator_bundle_index.py` is a passive review helper for the final firstboot release-gate handoff chain. It consumes the quoted `.summary.env` sidecar emitted by the operator-bundle smoke helper and inventories expected aggregate evidence artifacts so an operator, release gate, or recovery handoff can see whether the final bundle is complete.

## Generated artifacts

The `firstboot_release_gate.service` refreshes both machine-readable and operator-readable outputs:

- `/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.json`
- `/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.md`
- `/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.summary.env`

The helper records artifact paths, presence, byte size, and UTC modification time. It reports missing or zero-byte artifacts as review blockers instead of repairing them automatically.

## Threat-model rationale

The index is intentionally passive. It does not source shell content, inspect raw telemetry, open sockets, modify firewall rules, mutate services, approve restores, start persistence, change model files, update datasets, or alter host/VM state. It only reads aggregate summary evidence and filesystem metadata for known firstboot handoff artifacts.

This supports secure-by-default image promotion by making incomplete firstboot evidence visible before a hardened Kali image is treated as release-ready.

## Compatibility

The helper uses only Python standard-library modules and is packaged into the custom ISO alongside the other firstboot release-gate helpers. The JSON contract is versioned with `schema_version: "1.0"`; Markdown output is for human review and should not be parsed as a stable API.

## Rollback

Rollback is safe and reversible: remove the helper from `build_custom_iso.sh`, remove the two `ExecStartPost=` lines from `firstboot_release_gate.service`, and delete generated `/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.*` artifacts. No live firewall, service, host, VM, approval, restore, model, or dataset state needs to be reverted.

## Follow-up work

- Feed the index summary into a top-level release receipt once all firstboot evidence helpers have stable status contracts.
- Add optional age thresholds for index artifacts after the upstream freshness helpers settle.
- Render the index in a GUI or text dashboard without including raw logs, captures, hostnames, usernames, credentials, model binaries, or datasets.
