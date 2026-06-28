# Firstboot release-gate handoff freshness

## Added

- Added `firstboot_release_gate_handoff_freshness.py`, a passive aggregate-only helper that evaluates the age of firstboot release-gate handoff verification evidence and verified required aggregate artifacts before ISO promotion, recovery review, or manager handoff.
- Added JSON and Markdown output for freshness evidence, including freshness policy, artifact ages, blockers, manager summary, handoff checklist, privacy exclusions, and rollback guidance.
- Packaged `firstboot_release_gate_handoff_freshness.py` into custom ISO builds so hardened images include the freshness helper by default.
- Wired `firstboot_release_gate.service` to refresh JSON and Markdown handoff freshness artifacts after handoff verification artifacts are generated.
- Added tests for current evidence approval, stale verified artifact fail-closed behavior, Markdown handoff evidence, documentation coverage, privacy exclusions, rollback guidance, packaging coverage, and service refresh coverage.
- Documented usage, firstboot service integration, output contract, threat-model rationale, compatibility notes, rollback guidance, and follow-up work in `docs/firstboot_release_gate_handoff_freshness.md`.

## Security

- The freshness helper is additive and passive: it reads only existing privacy-safe aggregate handoff verification evidence and filesystem metadata, then emits derived JSON or Markdown freshness evidence.
- The `--require-fresh` path exits non-zero when verification evidence is missing, malformed, deferred, privacy-scope mismatched, stale, or when verified required artifacts are missing or stale.
- The service refresh is additive and passive: it writes derived freshness artifacts under `/var/log` without opening sockets, changing firewall rules, modifying services, approving restores, altering host/VM settings, changing IDS models, or touching datasets.
- The helper intentionally avoids raw telemetry, credentials, packet captures, model binaries, datasets, private identifiers, live service changes, network changes, approval changes, recovery changes, and firstboot state changes.
