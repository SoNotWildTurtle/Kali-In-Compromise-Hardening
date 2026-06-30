# Repository Module Roadmap

This roadmap is a passive, documentation-only companion to `docs/repository_module_roadmap.json`. It maps major repository modules to owner roles, generated artifacts, validation focus, rollback procedures, and likely next increments so future work grows the hardening suite cohesively instead of producing isolated patches.

## Scope and safety model

The roadmap is read-only planning evidence. It does not run commands, open sockets, inspect raw telemetry, change firewall rules, mutate services, approve restores, retrain models, modify datasets, change host or VM state, manage credentials, or alter accounts.

Every future implementation that uses this roadmap should remain authorized, defensive, least-privilege, reversible, auditable, privacy-preserving, and secure by default. Any release, restore, host-hardening, VM-hardening, IDS, or firstboot action must keep explicit operator approval where approval is required.

## Module ownership map

| Module | Owner role | Primary focus | Generated evidence |
| --- | --- | --- | --- |
| Kali guest firstboot hardening | Kali guest hardening maintainer | Preseed, firstboot, VM hardening, release-gate wiring, systemd hardening | Firstboot release-gate JSON, Markdown, and `.summary.env` artifacts |
| Host/VM policy and isolation | Host and hypervisor isolation maintainer | Windows/Linux host hardening, VM environment restrictions, authorization, transport security, hypervisor-aware passive review | Host/VM firstboot manifest and handoff artifacts |
| NN IDS posture pipeline | NN IDS posture and release-gate maintainer | Dataset provenance, feature schema, health evidence, drift evidence, release checklist, model card | IDS health, posture bundle, model-card, checklist, and receipt artifacts |
| Recovery, restore, and release gates | Recovery and release readiness maintainer | Snapshot verification, restore-readiness evidence, bundle manifests, operator digests, fail-closed gates | Release-gate status, bundle manifest, operator digest, and receipt artifacts |
| Operator docs and CI static coverage | Documentation and validation maintainer | README, docs, changelog fragments, tests, workflows, rollback notes, static security checks | Changelog fragments, workflow logs, static test evidence |

## Validation strategy

Future increments should add or update tests that match the module being changed:

- Firstboot and packaging changes should validate helper installation, service/timer wiring, sandboxing, passive default behavior, and rollback notes.
- Host/VM policy changes should validate explicit authorization wording, credential handling guidance, transport assumptions, least-privilege boundaries, and no host mutation by default.
- NN IDS posture changes should validate data provenance, feature-schema coverage, freshness thresholds, drift evidence, model-card output, privacy-safe handoff language, and fail-closed behavior.
- Recovery and release-gate changes should validate missing evidence blockers, freshness blockers, Markdown/JSON contracts, summary sidecars, and no automatic restore approval.
- Documentation and CI changes should validate safe-default wording, rollback guidance, no secrets or raw telemetry, and compatibility notes.

## Next increment queue

1. Add a passive README duplicate-module drift check so repeated feature and project-structure entries are detected without deleting existing content.
2. Add configuration schema validation for `/etc/nn_ids.conf`, host/VM policy thresholds, artifact paths, and firstboot enablement choices.
3. Add hypervisor-specific passive risk evidence for VirtualBox, VMware, Hyper-V, and KVM/QEMU.
4. Add a unified aggregate posture gate that composes Kali guest readiness, host/VM isolation, NN IDS health, drift, model-card, release receipts, and rollback readiness.
5. Add a release checklist that blocks promotion when required documentation, rollback notes, tests, or passive evidence artifacts are missing.

## Review checklist

Before using this roadmap to drive code changes, confirm the selected increment:

- Is additive, cohesive, and reviewable.
- Repairs failing workflows or PR blockers before unrelated expansion.
- Preserves existing files, APIs, scripts, services, timers, docs, examples, tests, and operator workflows where practical.
- Does not weaken firewall posture, service hardening, host/VM isolation, update safety, IDS controls, privacy boundaries, or restore controls.
- Includes test evidence, documentation, compatibility impact, rollback guidance, and follow-up work.

## Rollback

Delete `docs/repository_module_roadmap.json`, `docs/repository_module_roadmap.md`, `docs/changelog_repository_module_roadmap.md`, and `tests/test_repository_module_roadmap.py`.

No live firewall, service, host, VM, IDS, approval, restore, model, dataset, account, credential, or network state requires rollback.
