# README Duplicate Module Drift Check

This note defines a passive documentation-quality check for repeated README feature and project-structure entries. It is intentionally non-mutating: it does not rewrite the README, delete historical wording, change package wiring, alter firstboot behavior, mutate services, modify firewall rules, inspect host or VM state, approve restores, touch IDS models or datasets, or open network connections.

## Purpose

The README is the operator's first map of the Kali hardening suite. Repeated module entries make it harder to distinguish current capabilities, planned work, rollback boundaries, and firstboot responsibilities. The check added with this document records the known duplicate-module drift in a testable way so future cleanup can be deliberate, reviewable, and safe instead of broad or subtractive.

## Current duplicate families

The current README contains repeated entries for several module families. These are treated as known documentation drift, not runtime defects:

- Automated Windows 11 host hardening.
- Automated Windows remote setup.
- Windows host-aware VM hardening.
- MAC address randomization.
- Neural network IDS.
- Packet sanitization.
- Initial network discovery.
- Firstboot project-structure wiring.
- Host hardening Windows project-structure wiring.
- VM Windows environment hardening project-structure wiring.
- Security scan scheduler project-structure wiring.
- Process and service monitoring project-structure wiring.
- Port socket monitoring project-structure wiring.
- NN IDS health and timer units project-structure wiring.
- Setup NN IDS project-structure wiring.

## Static check contract

The companion test scans `README.md` only as text and verifies that the known duplicate families are still discoverable. It does not fail just because duplicate content exists. Instead, it prevents accidental silent drift by requiring that repeated entries remain visible to reviewers until a dedicated cleanup PR intentionally updates this document and its test expectations.

A future cleanup PR can safely reduce duplicates by:

1. Collapsing repeated feature bullets into one canonical entry per capability.
2. Keeping compatibility notes for renamed or legacy modules.
3. Preserving all script names, artifact names, commands, and rollback notes.
4. Updating this document and `tests/test_readme_duplicate_module_drift.py` in the same PR.
5. Recording validation evidence showing that only documentation was normalized.

## Threat-model rationale

This is documentation and static validation only. It improves operator handoff quality and reviewability without weakening secure defaults or changing any active controls. The check is especially useful for automation runs because it turns a known documentation-debt item from the repository roadmap into a concrete, low-risk validation target.

## Rollback

Rollback requires deleting `docs/readme_duplicate_module_drift.md`, `docs/changelog_readme_duplicate_module_drift.md`, and `tests/test_readme_duplicate_module_drift.py`. No live host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, or account state requires rollback.

## Follow-up work

- Add a dedicated README normalization PR that removes duplicate bullets while preserving all capability coverage and script references.
- Add a README feature-to-module index that maps each documented capability to its implementation files, generated artifacts, and rollback guidance.
- Add a release checklist item requiring documentation-drift review before ISO promotion.
