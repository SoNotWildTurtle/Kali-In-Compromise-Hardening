# Firstboot release-gate bundle manifest

`firstboot_release_gate_bundle_manifest.py` creates a passive manifest for the firstboot release-gate evidence set. It records required artifact presence, sizes, and SHA-256 hashes for the JSON gate, Markdown gate, shell summary, and status-reader JSON output.

The helper is intended for ISO promotion, recovery bundle review, release handoff, and dashboards that need one machine-readable evidence index without collecting private operational details.

## Usage

Generate the status-reader JSON first:

```bash
python3 firstboot_release_gate_status.py \
  --summary /var/log/firstboot_release_gate.summary.env \
  --format json \
  --require-pass > /var/log/firstboot_release_gate.status.json
```

Then build the bundle manifest:

```bash
python3 firstboot_release_gate_bundle_manifest.py \
  --gate-json /var/log/firstboot_release_gate.json \
  --gate-markdown /var/log/firstboot_release_gate.md \
  --summary /var/log/firstboot_release_gate.summary.env \
  --status-json /var/log/firstboot_release_gate.status.json \
  --output /var/log/firstboot_release_gate.bundle_manifest.json \
  --require-pass
```

With `--require-pass`, the command exits `7` when any required artifact is missing, the status JSON is malformed, the status component is unexpected, the status is not passing, or status validation blockers are present.

## Output contract

The manifest emits JSON with:

- `decision`, `release_gate`, and `ok` for bundle promotion status.
- Four required artifact records with `path`, `exists`, `size_bytes`, and `sha256` fields.
- A compact `status_summary` copied from the status-reader JSON.
- Machine-readable `blockers` and `operator_next_steps`.
- `privacy_scope`, `privacy_exclusions`, `safe_default`, and `rollback_note` fields.

## Design rationale

Evidence bundles are useful for release handoff, but bundle tools should avoid collecting private system evidence by accident. This helper records only artifact references, sizes, and hashes. It does not parse the authoritative JSON or Markdown contents beyond hashing bytes, and it validates only the aggregate status-reader JSON.

The helper does not open network sockets, execute host commands, restart services, modify firewall rules, change service state, approve restores, update firstboot state, or touch NN IDS models and datasets.

## Compatibility

The helper uses only the Python standard library and is safe for Kali/Debian Python 3 environments. It does not require root privileges, systemd, network access, or external packages.

## Rollback

Rollback is additive and low risk:

1. Stop invoking `firstboot_release_gate_bundle_manifest.py` from release, recovery, dashboard, or ISO promotion scripts.
2. Continue reviewing the JSON, Markdown, summary, and status artifacts individually.
3. Remove the helper from custom ISO packaging if desired.
4. Revert this helper, tests, docs, packaging entry, and changelog entry.

No upstream firstboot manifest, NN IDS model card, release-gate JSON, release-gate Markdown, summary file, status file, host setting, VM setting, firewall rule, service state, approval, restore state, model file, or dataset is modified by this helper.

## Follow-up work

- Add a release-gate service option that writes `/var/log/firstboot_release_gate.status.json` after each passive timer run.
- Add an optional dashboard view that reads the bundle manifest and displays artifact hash mismatches or missing evidence.
