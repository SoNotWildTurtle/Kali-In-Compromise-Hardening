# Changelog

## Unreleased

### Added

- Added optional `--max-artifact-age-minutes` freshness gating to `nn_ids_posture_bundle_manifest.py`, allowing release, firstboot, and recovery workflows to fail stale NN IDS evidence without embedding raw logs or captures.
- Added `tests/test_nn_ids_posture_bundle_freshness_static.sh` to cover stale artifact blockers, freshness policy output, Markdown freshness reporting, and `--require-pass` behavior.
- Added Markdown handoff rendering to `nn_ids_posture_bundle_manifest.py` via `--format markdown`, preserving the existing JSON contract while giving operators a privacy-safe review artifact with release-gate status, artifact summaries, blockers, warnings, privacy notes, and rollback guidance.
- Extended `tests/test_nn_ids_posture_bundle_manifest_static.sh` to cover Markdown output, privacy/rollback text, warning propagation, and the existing missing-artifact release gate path.
- Added `nn_ids_posture_bundle_manifest.py`, a passive privacy-safe release-gate manifest that aggregates NN IDS health, drift, and triage evidence into one machine-readable posture bundle.
- Added `docs/nn_ids_posture_bundle_manifest.md` with usage, schema, release-gate behavior, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.
- Added `tests/test_nn_ids_posture_bundle_manifest_static.sh` covering compile validation, pass/warn aggregation, SHA-256 artifact hashes, privacy/rollback fields, missing artifact blockers, and `--require-pass` behavior.
- Added `nn_ids_drift_triage.py`, a read-only renderer that converts passive NN IDS drift evidence into privacy-safe Markdown or JSON operator handoff artifacts.
- Added `docs/nn_ids_drift_triage.md` with usage, release-gate behavior, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.
- Added tests covering drift triage summary counts, recommended actions, Markdown rendering, privacy notes, rollback notes, and `--require-pass` exit behavior.
- Added `nn_ids_drift_evidence.py`, a passive JSON evidence emitter that compares baseline and current NN IDS feature statistics for PSI, mean-shift, and missing-rate drift before model or release promotion.
- Added `docs/nn_ids_drift_evidence.md` with input schema, examples, thresholds, rollback notes, and follow-up work for posture-summary and dashboard integration.
- Added `tests/test_nn_ids_drift_evidence_static.sh` covering pass/fail drift evidence, `--require-pass`, JSON output, canonical four-feature coverage, and compile validation.
- Added `nn_ids_health_evidence.py`, a passive JSON evidence emitter for NN IDS model freshness, latest training metrics, service-health log markers, and readable capture/dataset inputs.
- Added `nn_ids_health_evidence.service` and `nn_ids_health_evidence.timer` to publish passive IDS posture evidence to `/var/log/nn_ids_health_evidence.json` on a recurring schedule.
- Packaged the NN IDS health evidence emitter, service, and timer in `build_custom_iso.sh` and wired firstboot to enable the timer plus write an immediate firstboot evidence artifact.
- Added static and behavior-oriented coverage in `tests/test_nn_ids_health_evidence_static.sh` for packaging, systemd hardening, passing posture, low metric failures, restart warnings, and missing model failures.
- Added `docs/NN_IDS_HEALTH_EVIDENCE.md` with usage, deployment integration, schema, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.

### Security

- The posture bundle freshness gate is passive and privacy-safe: it uses only each evidence artifact's aggregate `generated_at` timestamp and never reads raw packets, payloads, captures, credentials, hostnames, usernames, secrets, or raw IDS logs.
- The Markdown posture bundle handoff is generated from aggregate manifest evidence only; it does not embed raw packets, payloads, captures, credentials, hostnames, usernames, secrets, or raw IDS logs.
- The NN IDS posture bundle manifest is read-only and privacy-safe: it records only artifact paths, SHA-256 digests, aggregate statuses, and control IDs, without embedding packets, payloads, credentials, hostnames, usernames, raw captures, or secrets.
- The posture bundle `--require-pass` path exits non-zero when required health, drift, or triage artifacts are missing or failing, making release gates auditable without changing firewall, service, model, dataset, or host/VM state.
- The NN IDS drift triage renderer is read-only and privacy-safe: it consumes aggregate drift evidence and does not include packets, payloads, credentials, host secrets, or raw captures in generated handoffs.
- The NN IDS drift evidence emitter is read-only: it does not open network sockets, execute commands, restart services, change firewall rules, or modify host/VM state.
- Drift failures are treated as review gates for analytical trust and model promotion, not as certain indications of malicious traffic or operational targeting.
- The NN IDS evidence emitter is read-only: it does not open network sockets, execute commands, restart services, change firewall rules, or modify host/VM state.
- `nn_ids_health_evidence.service` uses systemd hardening controls including `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`, an empty capability bounding set, `ReadOnlyPaths=/opt/nnids`, and `ReadWritePaths=/var/log`.
- `--require-pass` exits non-zero when model evidence, metric evidence, or recent health markers indicate degraded IDS posture.
