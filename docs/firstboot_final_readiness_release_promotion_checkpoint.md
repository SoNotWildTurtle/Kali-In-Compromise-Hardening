# Firstboot release promotion checkpoint

`firstboot_final_readiness_release_promotion_checkpoint.py` is a passive aggregate-only checkpoint for the end of the firstboot final-readiness handoff chain. It reads the quoted `.summary.env` output from `firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py` and emits JSON, Markdown, and optional summary evidence for operator release review.

## Purpose

The helper gives release reviewers a compact final checkpoint after the release-receipt handoff digest smoke index. It validates that the upstream index reported a pass decision, zero blockers, aggregate-only privacy scope, and the expected minimum artifact count before ISO promotion, branch promotion, or recovery handoff proceeds.

The design stays aligned with secure-by-default control evidence patterns: it is auditable, least-privilege, reversible, and additive to the existing firstboot release-gate chain.

## Inputs

Default input:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.summary.env
```

Required quoted keys:

```text
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_INDEX_STATUS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_INDEX_BLOCKERS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_INDEX_WARNINGS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_INDEX_ARTIFACTS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_INDEX_PRIVACY_SCOPE
```

The parser does not source shell content. Malformed lines are ignored and reported as warnings.

## Outputs

Default JSON output:

```text
/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.json
```

Default summary output:

```text
/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.summary.env
```

Markdown output is available with `--format markdown` and is wired by `firstboot_release_gate.service` to:

```text
/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.md
```

## Decision contract

The checkpoint reports `ready` only when:

- the upstream smoke-index status is `pass`;
- the upstream smoke-index blocker count is zero;
- the privacy scope is `aggregate_metadata_only`;
- the upstream artifact count meets the expected floor; and
- all required summary keys parse as non-negative integers where expected.

Any failure returns `hold`. Operators can use `--require-ready` to make hold status exit non-zero in stricter local release scripts.

## Threat-model rationale

This helper is intentionally passive. It does not open sockets, collect credentials, inspect raw packets, alter firewall rules, mutate systemd state, approve restores, write IDS models or datasets, or change host or VM configuration. Its role is to make formatting-sensitive promotion evidence failures visible before branch promotion, ISO publishing, or recovery handoff.

## Systemd and packaging integration

`build_custom_iso.sh` packages the helper beside the existing firstboot release-gate modules. `firstboot_release_gate.service` appends JSON and Markdown `ExecStartPost=` steps after the handoff digest smoke index artifacts are created.

The existing service sandbox remains in place with `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`, kernel/control-group protections, an empty capability bounding set, read-only evidence inputs, and `/var/log` as the only write path for generated evidence.

## Rollback

To roll this helper back:

1. Remove `firstboot_final_readiness_release_promotion_checkpoint.py` from `build_custom_iso.sh`.
2. Remove the two release promotion checkpoint `ExecStartPost=` lines from `firstboot_release_gate.service`.
3. Delete generated `/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.*` artifacts.

No live firewall, service, host, VM, IDS, approval, restore, model, dataset, account, credential, or network state requires rollback.

## Known limitations

This validates only the aggregate smoke-index summary contract. It does not replace repository CI, required checks, review-thread resolution, branch protection, manual review of upstream JSON/Markdown artifacts, or stacked PR dependency verification.

## Follow-up work

Feed this checkpoint into the aggregate posture report or operator dashboard once the final-readiness handoff chain stabilizes.
