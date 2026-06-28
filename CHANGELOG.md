# Changelog

## Unreleased

### Added

- Added `firstboot_final_readiness_smoke.py`, a passive aggregate-only smoke gate for the final-readiness `.summary.env` sidecar that validates the quoted `FIRSTBOOT_FINAL_READINESS_*` contract without sourcing shell content.
- Packaged the final-readiness smoke helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` smoke artifacts, and added static coverage for approved evidence, privacy-scope fail-closed behavior, packaging, service wiring, documentation, rollback notes, and changelog coverage.
- Added `firstboot_release_gate_handoff_freshness.py`, a passive aggregate-only freshness gate that evaluates the age of firstboot release-gate handoff verification evidence and verified required aggregate artifacts before ISO promotion, recovery review, or manager handoff.
- Added JSON and Markdown freshness evidence with policy thresholds, artifact ages, blockers, manager summary, handoff checklist, privacy exclusions, rollback guidance, and `--require-fresh` release-gate behavior.
- Added `docs/firstboot_release_gate_handoff_freshness.md`, a changelog fragment, and tests for current evidence approval, stale verified artifact fail-closed behavior, Markdown handoffs, documentation coverage, privacy exclusions, and rollback guidance.
- Added `firstboot_release_gate_operator_digest.py`, a passive aggregate-only operator digest that composes firstboot release-gate status JSON and bundle manifest JSON into manager-readable JSON or Markdown handoff evidence.
- Packaged the operator digest helper into custom ISO builds and wired `firstboot_release_gate.service` to refresh JSON and Markdown digest artifacts after status and bundle manifests are generated.
- Added `docs/firstboot_release_gate_operator_digest.md` plus tests for approved digests, deferred Markdown handoffs, source mismatch blockers, privacy exclusions, rollback guidance, and `--require-pass` behavior.
- Added `--format markdown` to `firstboot_release_gate_status.py`, giving operators, dashboards, recovery bundles, and shift handoffs a privacy-safe readable status artifact derived from the same validated aggregate summary used for text and JSON.
- Added Markdown status coverage for approved and deferred firstboot release-gate summaries, including validation blockers, safety/privacy notes, rollback guidance, and `--require-pass` exit behavior.
- Wired `firstboot_release_gate.service` to refresh `/var/log/firstboot_release_gate.status.json`, `/var/log/firstboot_release_gate.bundle_manifest.json`, and `/var/log/firstboot_release_gate.bundle_manifest.md` after the passive release-gate artifacts are generated, keeping hourly handoff evidence coherent for dashboards, release review, and recovery bundles.
- Extended `tests/test_firstboot_release_gate_timer_static.sh` to compile the status and bundle helpers and verify the service emits status JSON plus both JSON and Markdown bundle manifests while preserving sandboxing and passive timer behavior.
- Added `--format markdown` to `firstboot_release_gate_bundle_manifest.py`, giving operators a privacy-safe readable bundle handoff report with status summary, artifact hashes, blockers, next steps, safety notes, and rollback guidance while preserving the existing JSON default and `--require-pass` behavior.
- Added `tests/test_firstboot_release_gate_bundle_manifest_markdown.py` to cover passing Markdown output, deferred release-gate Markdown output, privacy exclusions, safe-default language, rollback text, and non-zero `--require-pass` behavior.
- Packaged `firstboot_release_gate_bundle_manifest.py` into custom ISO builds so hardened images include the passive aggregate evidence bundle manifest helper by default.
- Added `tests/test_firstboot_release_gate_bundle_packaging_static.sh` to cover helper compilation, ISO packaging, documentation, changelog, and rollback guidance for the bundle manifest packaging path.
- Added `firstboot_release_gate_status.py`, a passive aggregate-only reader for `firstboot_release_gate.summary.env` that emits text or JSON status for dashboards, smoke checks, shift handoffs, and release gates without sourcing shell content.
- Added `docs/firstboot_release_gate_status.md`, packaging coverage, and tests for passing summaries, deferred status, malformed summary validation, privacy-scope enforcement, and text output.
- Added `docs/firstboot_release_gate_operator_summary_contract.md`, defining a privacy-safe shell-friendly firstboot release-gate summary artifact for dashboards, release scripts, recovery runbooks, and future implementation coverage.
- Added `firstboot_release_gate.service` and `firstboot_release_gate.timer`, a passive recurring refresh path for firstboot release-gate JSON/Markdown handoff evidence.
- Packaged the firstboot release-gate timer units in `build_custom_iso.sh`, enabled the timer from `firstboot.sh`, added an immediate non-blocking firstboot gate run, and added static coverage for packaging, firstboot wiring, systemd sandboxing, passive/offline behavior, and timer cadence.
- Updated `docs/firstboot_release_gate.md` with timer workflow, generated artifacts, sandboxing rationale, rollback guidance, compatibility notes, and follow-up work.
- Added `firstboot_release_gate.py`, a passive gate that composes host/VM firstboot manifest readiness and NN IDS model-card readiness into one privacy-safe JSON/Markdown release decision for ISO promotion, firstboot handoff, and recovery review.
- Packaged `firstboot_release_gate.py` in `build_custom_iso.sh` and added static coverage for approved gates, deferred NN IDS gates, missing evidence, invalid freshness thresholds, Markdown rendering, privacy text, and packaging regression checks.
- Added `docs/firstboot_release_gate.md` with usage, output contract, threat-model rationale, compatibility notes, rollback guidance, and follow-up work.
- Added opt-in `--max-artifact-age-minutes` freshness gating to `host_vm_policy_firstboot_manifest.py`, allowing firstboot and release reviewers to block stale or clock-skewed host/VM handoff artifacts without reading raw telemetry or changing host/VM state.
- Added `mtime_utc`, `age_seconds`, and `freshness_policy` fields to firstboot handoff manifests, plus Markdown freshness reporting and static coverage for passing freshness, stale artifact blockers, invalid threshold input, and unchanged default behavior.
- Added `host_vm_policy_firstboot_manifest.py`, a passive manifest helper that records firstboot handoff artifact presence, sizes, SHA-256 digests, decisions, blockers, rollback guidance, and operator next steps.
- Packaged `host_vm_policy_firstboot_manifest.py` in `build_custom_iso.sh` and added static coverage for approved manifests, missing required artifact blockers, deferred handoff blockers, Markdown rendering, privacy notes, and `--require-ready` behavior.
- Added `docs/host_vm_policy_firstboot_manifest.md` with usage, output contract, privacy/security rationale, compatibility notes, rollback guidance, and follow-up work.

### Security

- The final-readiness smoke gate is additive and passive: it validates only the quoted aggregate final-readiness summary sidecar, emits derived smoke evidence, and does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, or modify host/VM state.
- The smoke helper `--require-pass` path exits non-zero when final-readiness evidence is missing, malformed, privacy-scope mismatched, internally inconsistent, blocker-inconsistent, artifact-empty, or marked pass while failed.
- The firstboot release-gate handoff freshness helper is additive and passive: it reads only existing aggregate verification evidence and filesystem metadata, emits derived freshness evidence, and does not change host, VM, firewall, service, model, dataset, approval, restore, network, or firstboot state.
- The freshness helper `--require-fresh` path exits non-zero when verification evidence is missing, malformed, deferred, privacy-scope mismatched, stale, or when verified required artifacts are missing or stale.
- The firstboot release-gate operator digest is additive and passive: it summarizes aggregate status and bundle manifest JSON for handoff review without changing services, timers, firewall rules, models, datasets, approvals, restore state, host settings, VM settings, or firstboot state.
- The operator digest `--require-pass` path exits non-zero when status and bundle evidence are missing, malformed, failing, mismatched, blocked, incomplete, or missing required SHA-256 artifact references.
- The firstboot release-gate status Markdown output is additive and passive: it renders validated aggregate summary fields only and does not change host, VM, firewall, service, model, dataset, approval, restore, or firstboot state.
- The Markdown output preserves the existing fail-closed status-reader behavior for malformed summaries, privacy-scope mismatches, deferred gate state, stale/skewed evidence, and `--require-pass` exits.
- The firstboot release-gate service refresh is additive and passive: it writes derived aggregate status and bundle manifest files after the existing release-gate command without opening sockets, changing firewall rules, approving restores, or modifying host, VM, IDS, model, dataset, approval, restore, or firstboot state.
- The status refresh is best-effort and the bundle manifest remains fail-closed when upstream status evidence is missing, malformed, deferred, stale, or blocked.
