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

## Timer workflow

`firstboot_release_gate.service` and `firstboot_release_gate.timer` provide a passive recurring refresh path for release and firstboot evidence. The timer is packaged into custom ISO builds and enabled during `firstboot.sh` when the unit is present.

The timer runs after boot and then hourly:

```bash
sudo systemctl enable --now firstboot_release_gate.timer
sudo systemctl status firstboot_release_gate.timer
sudo systemctl cat firstboot_release_gate.service
```

The service writes:

- `/var/log/firstboot_release_gate.json`
- `/var/log/firstboot_release_gate.md`
- `/var/log/firstboot_release_gate.firstboot.log` for the immediate firstboot invocation

The immediate firstboot run uses `FIRSTBOOT_RELEASE_GATE_MAX_AGE_MINUTES` when set, defaulting to `240` minutes. It does not use `--require-pass`, so incomplete early boot evidence is recorded as a deferred handoff rather than breaking firstboot.

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

This gate addresses the operational gap between host/VM policy evidence and NN IDS model-promotion evidence. Both can pass independently while an operator still lacks a single release artifact proving the firstboot handoff and IDS posture are ready together. The recurring timer makes that combined readiness available after firstboot evidence matures, without waiting for an operator to remember a manual command.

## Privacy and safety

The helper and timer are read-only. They do not open network sockets, execute host commands, restart services, alter firewall rules, change model files, update datasets, approve restore actions, or modify firstboot state. They record only aggregate status labels, paths, mtimes, ages, sizes, SHA-256 digests, blocker labels, and next-step text.

The service is sandboxed with `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`, `ProtectKernelTunables=true`, `ProtectKernelModules=true`, `ProtectControlGroups=true`, an empty capability bounding set, read-only access to the expected input artifacts, and write access only to `/var/log`.

## Compatibility

The helper uses only the Python standard library and works with Python 3 on Kali/Debian-like systems. It is packaged into the custom ISO by `build_custom_iso.sh` and can also be run manually from a cloned checkout. The timer uses standard systemd unit and timer directives supported on modern Kali/Debian systems.

## Rollback

Rollback is additive and low risk:

1. Disable the recurring refresh with `sudo systemctl disable --now firstboot_release_gate.timer`.
2. Stop calling `firstboot_release_gate.py` from release or firstboot review scripts.
3. Delete generated `/var/log/firstboot_release_gate.json`, `/var/log/firstboot_release_gate.md`, and `/var/log/firstboot_release_gate.firstboot.log` artifacts if desired.
4. Revert the helper, timer units, docs, packaging entry, firstboot wiring, and static test.

Upstream firstboot manifest and NN IDS model-card artifacts are never modified by this helper or timer.

## Follow-up work

- Feed the release-gate JSON into a future aggregate operations dashboard.
- Add a release workflow step that archives the JSON/Markdown outputs with build evidence once repository policy is ready.
- Consider a dedicated `/etc/default/firstboot_release_gate` environment file if multiple deployments need different freshness thresholds.
