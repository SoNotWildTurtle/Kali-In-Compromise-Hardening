#!/usr/bin/env bash
# MINC - Static validation for passive release promotion checkpoint packaging.
set -euo pipefail

python3 -m py_compile firstboot_final_readiness_release_promotion_checkpoint.py

grep -q 'firstboot_final_readiness_release_promotion_checkpoint.py' build_custom_iso.sh
grep -q 'firstboot_final_readiness_release_promotion_checkpoint.py --input /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.summary.env --format json' firstboot_release_gate.service
grep -q 'firstboot_final_readiness_release_promotion_checkpoint.py --input /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.summary.env --format markdown' firstboot_release_gate.service

grep -q 'NoNewPrivileges=true' firstboot_release_gate.service
grep -q 'ProtectSystem=full' firstboot_release_gate.service
grep -q 'CapabilityBoundingSet=' firstboot_release_gate.service

grep -q 'passive aggregate-only checkpoint' docs/firstboot_final_readiness_release_promotion_checkpoint.md
grep -q 'does not source shell content' docs/firstboot_final_readiness_release_promotion_checkpoint.md
grep -q 'Rollback' docs/firstboot_final_readiness_release_promotion_checkpoint.md

grep -q 'passive_release_promotion_checkpoint_only_no_host_vm_firewall_service_network_restore_or_model_changes' firstboot_final_readiness_release_promotion_checkpoint.py
grep -q 'No live firewall, service, host, VM, IDS, approval, restore, model, dataset, account, credential, or network state requires rollback.' firstboot_final_readiness_release_promotion_checkpoint.py

grep -q 'firstboot_final_readiness_release_promotion_checkpoint.py' docs/changelog_release_promotion_checkpoint.md
grep -q 'release promotion checkpoint' docs/changelog_release_promotion_checkpoint.md
