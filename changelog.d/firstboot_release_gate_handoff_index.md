# Firstboot release-gate handoff index

## Added

- Added `firstboot_release_gate_handoff_index.py`, a passive aggregate-only handoff index that records status, bundle manifest, and operator digest artifacts with SHA-256 hashes, required-artifact checks, and cross-artifact decision consistency validation.
- Packaged the handoff index helper into custom ISO builds and wired `firstboot_release_gate.service` to refresh JSON and Markdown handoff indexes after existing status, bundle manifest, and operator digest artifacts are generated.
- Added `docs/firstboot_release_gate_handoff_index.md` plus static coverage for approved indexes, deferred missing-required-artifact behavior, Markdown rendering, service wiring, packaging, privacy exclusions, and rollback guidance.

## Security

- The handoff index is additive and passive: it summarizes and hashes aggregate release-gate artifacts without opening sockets, changing firewall rules, restarting services, approving restores, modifying host/VM settings, or touching IDS models and datasets.
- The `--require-ready` path exits non-zero when required aggregate status, bundle manifest, or operator digest JSON artifacts are missing, malformed, failing, or inconsistent, preserving fail-closed release and recovery handoff behavior.
