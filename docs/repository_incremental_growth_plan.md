# Repository Incremental Growth Plan

This plan gives future maintainers and automation runs a durable decision framework for growing Kali-In-Compromise-Hardening as a cohesive defensive hardening suite instead of a sequence of isolated evidence-only patches.

## Purpose

Each iteration should produce a mergeable, reviewable, additive improvement that measurably advances the repository as a complete product. The preferred outcome is a small but meaningful fix or functional expansion with tests, documentation, rollback notes, and clear follow-up work.

The plan is intentionally repository-wide. It applies to Kali guest hardening, host-to-VM and VM-to-host isolation, authenticated and encrypted communications, hypervisor-aware controls, secure update and rollback workflows, logging, policy enforcement, configuration validation, recovery, usability, packaging, firstboot wiring, systemd hardening, and the neural-network IDS posture pipeline.

## Operating principles

- Fix failing pull requests, workflows, packaging, firstboot wiring, service sandboxing, generated artifact contracts, or branch-stack problems before unrelated feature work.
- Preserve existing files, APIs, scripts, services, documentation, tests, examples, and operator workflows wherever practical.
- Prefer additive extensions that compose with existing modules rather than broad rewrites or replacements.
- Keep changes reversible, least-privilege, auditable, and secure by default.
- Treat IDS outputs as defensive analytical evidence, not targeting certainty.
- Avoid persistence, evasion, unauthorized access, weakened controls, destructive repository operations, and speculative rewrites.
- Record follow-up work so later runs build on prior progress instead of rediscovering the same gaps.

## Goal hierarchy

### Near-term goals

Near-term work should improve confidence in the current hardening suite and reduce recurring review friction.

- Repair failing CI, static security checks, packaging checks, firstboot checks, release-gate workflows, and formatting-sensitive tests.
- Add focused regression coverage for brittle wiring points such as `build_custom_iso.sh`, systemd unit sandboxing, generated `.summary.env` contracts, firstboot artifact paths, and passive evidence helpers.
- Improve documentation for current commands, generated artifacts, rollback steps, privacy boundaries, and safe operator review.
- Add validation helpers that are passive by default and fail closed when evidence is missing, malformed, stale, or internally inconsistent.
- Reduce duplicate README entries and clarify module ownership without removing functionality.

### Medium-term goals

Medium-term work should turn existing modules into coherent end-to-end defensive workflows.

- Connect Kali guest hardening, host hardening, VM environment hardening, firstboot evidence, and rollback documentation into one operator-readable posture report.
- Add configuration validation for host/VM policy, IDS thresholds, snapshot paths, artifact freshness thresholds, and service enablement choices before firstboot or ISO promotion.
- Improve secure host-to-VM and VM-to-host communication guidance around explicit authorization, credential handling, transport encryption, least privilege, and logging.
- Add hypervisor-aware checks for VirtualBox, VMware, Hyper-V, and KVM/QEMU that report risk posture without mutating host state by default.
- Expand safe recovery flows that can verify snapshots, backups, rollback instructions, and restore readiness without approving or applying a restore automatically.
- Make generated JSON, Markdown, and `.summary.env` artifacts easier for dashboards, release gates, and handoff reviews to consume consistently.

### Long-term goals

Long-term work should make the repository a comprehensive, defensible Kali VM and host hardening suite.

- Produce a unified aggregate posture gate that combines guest hardening, host/VM isolation, firstboot readiness, NN IDS health, drift, model-card, release receipts, rollback readiness, and documentation completeness.
- Mature the NN IDS pipeline with defensible feature engineering, data-quality checks, reproducible training metadata, model evaluation, drift detection, explainability, alert triage, adversarial robustness notes, and low-overhead inference evidence.
- Provide secure-by-default operator workflows for first install, firstboot, review, release promotion, incident handoff, recovery planning, rollback, and update verification.
- Maintain a clear compatibility matrix for Kali/Debian versions, Windows host assumptions, Linux host assumptions, hypervisors, systemd behavior, and optional dependencies.
- Keep all automation reversible, auditable, consent-based, and bounded to authorized systems.

## Per-run selection process

Every run should make an explicit local decision before editing files:

1. Inspect default branch, open pull requests, recent commits, workflow status, branch protection signals, review threads, and dependency order.
2. If anything is failing, repair that exact blocker first and validate the narrowest reproduction before broader tests.
3. If the repository is healthy, choose the highest-value additive increment from the goal hierarchy.
4. Prefer changes that unlock future work, reduce recurring maintenance cost, improve usability, strengthen safety, or close a known validation gap.
5. Keep the increment cohesive enough for one professional pull request.
6. Add tests and documentation proportional to the change.
7. Record remaining risks and follow-up work in the PR body or docs.

## Review checklist

Before publishing a pull request, verify that the change:

- Is additive and does not remove working functionality.
- Has a clear threat-model rationale.
- Preserves least privilege and secure defaults.
- Does not weaken service hardening, firewall posture, update safety, IDS controls, or privacy boundaries.
- Does not include secrets, generated binary artifacts, raw telemetry, credentials, or environment-specific identifiers.
- Includes rollback notes for any installed file, packaged helper, service unit, timer, or generated artifact.
- Includes exact validation evidence or a precise blocker when validation is still pending.

## Follow-up queue

Useful future increments include:

- Add a machine-readable repository roadmap artifact that maps modules to owners, generated artifacts, tests, and rollback procedures.
- Add a passive aggregate posture summary that links firstboot release gates with NN IDS posture gates and host/VM policy evidence.
- Add static coverage for README duplicate-module drift and documentation freshness.
- Add hypervisor-specific passive risk evidence for VirtualBox, VMware, Hyper-V, and KVM/QEMU.
- Add configuration schema validation for `/etc/nn_ids.conf` and host/VM policy thresholds.
- Add a release checklist that blocks promotion when required documentation, rollback notes, tests, or passive evidence artifacts are missing.

## Rollback

This document is guidance-only. Rolling it back requires deleting `docs/repository_incremental_growth_plan.md` and any static tests that reference it. No live firewall, service, host, VM, IDS, approval, restore, model, dataset, account, credential, or network state requires rollback.
