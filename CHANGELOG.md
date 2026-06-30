# Changelog

## Unreleased

### Added

- Added `docs/host_vm_policy_configuration_schema.json`, a passive JSON Schema contract for host/VM policy configuration review that preserves defensive-use authorization, explicit operator acknowledgement, aggregate-only evidence, bounded freshness settings, privacy exclusions, and file-only rollback before future firstboot or release-gate wiring.
- Added `docs/host_vm_policy_configuration_schema.md`, `docs/changelog_host_vm_policy_configuration_schema.md`, and `tests/test_host_vm_policy_configuration_schema.py` with example policy guidance, threat-model rationale, compatibility notes, rollback notes, and static coverage for schema safety boundaries.
- Added `firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py`, a passive aggregate-only index for final firstboot release-receipt handoff digest smoke evidence that validates the quoted smoke summary contract and records expected JSON, Markdown, and summary artifacts without changing host, VM, IDS, approval, restore, network, firewall, or service state.
- Packaged the handoff digest smoke index helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` index artifacts, and added documentation plus static coverage for helper execution, packaging, service wiring, sandboxing, passive safety wording, and rollback notes.
- Added `firstboot_final_readiness_operator_bundle_index.py`, a passive operator-facing index for final firstboot readiness bundle artifacts that inventories required JSON/Markdown/summary evidence without changing host, VM, IDS, approval, restore, network, firewall, or service state.
- Packaged the operator-bundle index helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` index artifacts, and added static coverage for helper execution, packaging, service wiring, and passive safety wording.
- Added `firstboot_final_readiness_manifest_smoke.py`, a passive aggregate-only smoke gate for the final-readiness manifest `.summary.env` sidecar that validates the quoted `FIRSTBOOT_FINAL_READINESS_MANIFEST_*` contract without sourcing shell content.
- Packaged the final-readiness manifest smoke helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` manifest smoke artifacts, and documented approval, rollback, privacy, safe-default behavior, and static coverage.
