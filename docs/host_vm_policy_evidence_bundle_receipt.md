# Host VM Policy Evidence Bundle Receipt

`host_vm_policy_evidence_bundle_receipt.py` is a passive handoff and release-gate helper for `policy_evidence_bundle.json`. It converts the aggregate bundle status into an explicit `approved` or `deferred` receipt that can be attached to release notes, firstboot review, recovery review, or operator handoff.

The receipt is intentionally additive and read-only. It reads one existing bundle, writes JSON plus Markdown artifacts, and does not change live host or VM state, IDS models, datasets, approval records, restore records, services, or timers.

## Usage

Generate a receipt from the default bundle path:

```bash
sudo /usr/local/bin/host_vm_policy_evidence_bundle_receipt.py \
  --output /var/lib/host_vm_comm_guard/policy_evidence_bundle_receipt.json \
  --markdown /var/log/host_vm_policy_evidence_bundle_receipt.md
```

Fail closed when the receipt is not approved:

```bash
sudo /usr/local/bin/host_vm_policy_evidence_bundle_receipt.py --require-ready
```

Allow warning-only bundles to pass through an explicit operator decision:

```bash
sudo /usr/local/bin/host_vm_policy_evidence_bundle_receipt.py \
  --allow-warning-approval \
  --require-ready
```

## Decision contract

| Bundle status | Default receipt | With `--allow-warning-approval` | Release gate |
| --- | --- | --- | --- |
| `pass` | `approved` | `approved` | `pass` |
| `warn` | `deferred` | `approved` | `stop` or `pass` |
| `review` | `deferred` | `deferred` | `stop` |
| `fail` | `deferred` | `deferred` | `stop` |
| missing/invalid bundle | `deferred` | `deferred` | `stop` |

Use `--require-ready` in CI, firstboot promotion, or recovery handoff gates so a deferred receipt exits non-zero.

## Output fields

The JSON receipt includes:

- `decision`, `ok`, and `release_gate` for automation.
- `bundle_path`, `bundle_sha256`, and `bundle_status` for provenance.
- `component_statuses` and `review_items` for operator triage.
- `action_items` for safe next steps.
- `privacy_note`, `safe_default`, and `rollback_note` for handoff review.

The Markdown artifact mirrors the same decision in a human-readable format.

## Privacy and security rationale

The receipt is derived from aggregate bundle metadata only. It does not embed raw logs, captures, credentials, hostnames, usernames, secrets, or model files. The utility does not open network sockets or execute external commands.

This provides an auditable stop/go artifact without weakening any existing control. Warning approval is opt-in so automated promotion remains conservative by default.

## Compatibility

This utility builds on `host_vm_policy_evidence_bundle.py` and preserves that bundle schema. Existing scripts can continue consuming `policy_evidence_bundle.json`; the receipt is a new downstream artifact.

## Rollback

Remove generated receipt files and revert this utility, its static test, this document, the changelog entries, and the packaging entry in `build_custom_iso.sh`. No deployed service or live state needs to be disabled because the feature is manual and read-only.

## Follow-up work

- Link the receipt from aggregate hardening posture summaries.
- Add an optional firstboot release-gate wrapper that consumes the receipt without duplicating bundle logic.
- Add signed artifact support after repository-level signing policy is defined.
