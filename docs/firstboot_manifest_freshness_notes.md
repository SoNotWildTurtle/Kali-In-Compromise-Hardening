# Firstboot manifest freshness gate plan

This note defines the next additive increment for `host_vm_policy_firstboot_manifest.py`: an optional age check for generated handoff files.

## Goal

Add `--max-artifact-age-minutes` so reviewers can require recent firstboot handoff evidence before accepting a release packet.

## Expected behavior

- Existing behavior remains unchanged when the option is omitted.
- Each artifact entry records `mtime_utc` in addition to the current path, size, and SHA-256 fields.
- Present artifacts older than the threshold add a freshness blocker.
- Present artifacts with far-future modification times add a clock-skew blocker.
- `--require-ready` exits non-zero when freshness blockers exist.
- Markdown output includes the evaluated freshness status.

## Test plan

Extend `tests/test_host_vm_policy_firstboot_manifest_static.sh` to cover unchanged default behavior, a passing freshness run, a stale artifact run, invalid threshold values, and Markdown freshness rendering.

## Rollback

Revert the helper option, tests, and documentation. Generated manifest files may be removed independently.
