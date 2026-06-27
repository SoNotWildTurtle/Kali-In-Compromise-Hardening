# Firstboot release gate

`firstboot_release_gate.py` is a passive release and firstboot promotion helper that composes two privacy-safe readiness artifacts into one go/no-go decision:

- `host_vm_policy_firstboot_manifest.json` for host/VM policy handoff, packaging, receipt, freshness, and rollback evidence.
- `nn_ids_model_card.json` for NN IDS schema, health, drift, release receipt, freshness, and model-promotion evidence.

The helper is designed for ISO promotion, firstboot handoff, and recovery review workflows where an operator needs one machine-readable and human-readable artifact before accepting a hardened Kali image or firstboot handoff.

## Usage

```bash
python3 firstboot_release_gate.py \
  --firstboot-manifest /var/log/host_vm_policy_firstboot_manifest.json \
  --model-card /var/log/nn_ids_model_card.json \
  --output /var/log/firstboot_release_gate.json \
  --markdown /var/log/firstboot_release_gate.md \
  --max-artifact-age-minutes 240 \
  --require-pass
```

When `--require-pass` is set, the command exits non-zero unless both upstream artifacts are present, parseable, fresh when freshness is enabled, and ready.

## Output contract

The JSON output includes:

- `component`: always `firstboot_release_gate`.
- `decision`: `approved` or `deferred`.
- `release_gate`: `pass` or `stop`.
- `inputs`: aggregate status, decision, readiness, and blocker counts from the upstream host/VM and NN IDS evidence.
- `artifacts`: path, size, mtime, age, SHA-256, source component, source status, and source timestamp metadata for each input.
- `blockers`: machine-readable reasons that must be resolved before promotion.
- `operator_next_steps`: privacy-safe remediation guidance.

## Threat-model rationale

This gate addresses the operational gap between host/VM policy evidence and NN IDS model-promotion evidence. Both can pass independently while an operator still lacks a single release artifact proving the firstboot handoff and IDS posture are ready together. The new gate makes that combined readiness explicit without reading raw packets, logs, captures, model binaries, datasets, credentials, hostnames, usernames, or live host/VM state.

## Privacy and safety

The helper is read-only. It does not open network sockets, execute host commands, restart services, alter firewall rules, change model files, update datasets, approve restore actions, or modify firstboot state. It records only aggregate status labels, paths, mtimes, ages, sizes, SHA-256 digests, blocker labels, and next-step text.

## Compatibility

The helper uses only the Python standard library and works with Python 3 on Kali/Debian-like systems. It is packaged into the custom ISO by `build_custom_iso.sh` and can also be run manually from a cloned checkout.

## Rollback

Rollback is additive and low risk:

1. Stop calling `firstboot_release_gate.py` from release or firstboot review scripts.
2. Delete generated `/var/log/firstboot_release_gate.json` and `/var/log/firstboot_release_gate.md` artifacts if desired.
3. Revert the helper, docs, packaging entry, and static test.

Upstream firstboot manifest and NN IDS model-card artifacts are never modified by this helper.

## Follow-up work

- Add an optional systemd unit/timer only after deciding the right cadence for release versus firstboot use.
- Feed the release-gate JSON into a future aggregate operations dashboard.
- Add a release workflow step that archives the JSON/Markdown outputs with build evidence once repository policy is ready.
