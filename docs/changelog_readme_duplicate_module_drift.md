# Changelog: README Duplicate Module Drift Check

## Added

- Added `docs/readme_duplicate_module_drift.md` to document known README duplicate-module drift, review expectations, safe cleanup steps, rollback guidance, and follow-up work.
- Added `tests/test_readme_duplicate_module_drift.py` to passively scan `README.md` for known repeated feature and project-structure entries without rewriting documentation or changing runtime behavior.

## Security

- The check is documentation/static-validation only. It does not change host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, or account state.
- The check turns known documentation drift into explicit review evidence so future cleanup can be narrow, intentional, and non-destructive.

## Rollback

Delete `docs/readme_duplicate_module_drift.md`, `docs/changelog_readme_duplicate_module_drift.md`, and `tests/test_readme_duplicate_module_drift.py`. No deployed host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, or account state requires rollback.
