#!/usr/bin/env bash
# MINC - Static validation for the repository-wide incremental growth plan.
set -euo pipefail

DOC="docs/repository_incremental_growth_plan.md"
CHANGELOG_FRAGMENT="docs/changelog_repository_incremental_growth_plan.md"

[ -f "${DOC}" ]
[ -f "${CHANGELOG_FRAGMENT}" ]

grep -q 'mergeable, reviewable, additive improvement' "${DOC}"
grep -q 'Kali guest hardening' "${DOC}"
grep -q 'host-to-VM and VM-to-host isolation' "${DOC}"
grep -q 'authenticated and encrypted communications' "${DOC}"
grep -q 'systemd hardening' "${DOC}"
grep -q 'neural-network IDS posture pipeline' "${DOC}"
grep -q 'Fix failing pull requests, workflows, packaging, firstboot wiring, service sandboxing' "${DOC}"
grep -q 'Near-term goals' "${DOC}"
grep -q 'Medium-term goals' "${DOC}"
grep -q 'Long-term goals' "${DOC}"
grep -q 'Per-run selection process' "${DOC}"
grep -q 'Review checklist' "${DOC}"
grep -q 'Follow-up queue' "${DOC}"
grep -q 'No live firewall, service, host, VM, IDS, approval, restore, model, dataset, account, credential, or network state requires rollback.' "${DOC}"

grep -q 'repository_incremental_growth_plan.md' "${CHANGELOG_FRAGMENT}"
grep -q 'passive documentation-only' "${CHANGELOG_FRAGMENT}"
grep -q 'does not change host, VM, firewall, service, network, restore, approval, model, dataset, credential, or account state' "${CHANGELOG_FRAGMENT}"
grep -q 'Rollback' "${CHANGELOG_FRAGMENT}"
