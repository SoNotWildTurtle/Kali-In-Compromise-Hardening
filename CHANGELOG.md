# Changelog

## Unreleased

### Added

- Added `tests/test_nn_ids_release_report_contract_static.sh`, a dependency-free static contract test for the passive NN IDS release-readiness key/value report that verifies dashboard-safe fields mirror the JSON decision, preserve passive safety flags, and include blocking issue lines only for blocked summaries.
- Added `firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py`, a passive aggregate-only index for final firstboot release-receipt handoff digest smoke evidence that validates the quoted smoke summary contract and records expected JSON, Markdown, and summary artifacts without changing host, VM, IDS, approval, restore, network, firewall, or service state.
- Packaged the handoff digest smoke index helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` index artifacts, and added documentation plus static coverage for helper execution, packaging, service wiring, sandboxing, passive safety wording, and rollback notes.
- Added `firstboot_final_readiness_operator_bundle_index.py`, a passive operator-facing index for final firstboot readiness bundle artifacts that inventories required JSON/Markdown/summary evidence without changing host, VM, IDS, approval, restore, network, firewall, or service state.
- Packaged the operator-bundle index helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` index artifacts, and added static coverage for helper execution, packaging, service wiring, and passive safety wording.
- Added `firstboot_final_readiness_manifest_smoke.py`, a passive aggregate-only smoke gate for the final-readiness manifest `.summary.env` sidecar that validates the quoted `FIRSTBOOT_FINAL_READINESS_MANIFEST_*` contract without sourcing shell content.
- Packaged the final-readiness manifest smoke helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` manifest smoke artifacts, and documented approval, rollback, privacy, safe-default behavior, and static coverage.
- Added `firstboot_final_readiness_manifest.py`, a passive aggregate-only manifest helper for the final-readiness smoke `.summary.env` sidecar that validates the quoted `FIRSTBOOT_FINAL_READINESS_SMOKE_*` contract without sourcing shell content.
- Packaged the final-readiness manifest helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` manifest artifacts, and documented approval, rollback, privacy, and safe-default behavior.
- Added `firstboot_final_readiness_smoke.py`, a passive aggregate-only smoke gate for the final-readiness `.summary.env` sidecar that validates the quoted aggregate final-readiness summary sidecar without sourcing shell content.
- Packaged the final-readiness smoke helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` smoke artifacts, and added static coverage for approved evidence, privacy-scope fail-closed behavior, packaging, service wiring, documentation, rollback notes, and changelog coverage.

### Security

- The NN IDS release report contract test is additive and passive: it uses synthetic model-audit and audit-gate JSON, validates only generated aggregate JSON and key/value report artifacts, and does not read packets, datasets, models, live host/VM state, secrets, telemetry, services, firewall policy, or network configuration.
- The NN IDS release report contract preserves fail-closed behavior by requiring blocked `retrain` or `restore` summaries to emit machine-readable `blocking_issue` lines for release dashboards while leaving runtime IDS behavior unchanged.

### Validation

- Added focused validation command: `bash tests/test_nn_ids_release_report_contract_static.sh`.
