# Changelog note: release promotion checkpoint

## Unreleased

### Added

- Added `firstboot_final_readiness_release_promotion_checkpoint.py`, a passive aggregate-only final checkpoint for firstboot release-promotion evidence. It validates the quoted handoff digest smoke-index summary contract and emits JSON, Markdown, and `.summary.env` artifacts.
- Packaged the helper, wired `firstboot_release_gate.service` to refresh checkpoint artifacts, and documented the decision contract, sandboxing, rollback, privacy, and known limitations.

### Security

- The release promotion checkpoint is additive and passive: it reads only aggregate metadata summary evidence, does not source shell content, and reports missing, malformed, blocker-bearing, privacy-scope-mismatched, or low-artifact upstream evidence as `hold` rather than attempting automatic repair or weakening controls.
