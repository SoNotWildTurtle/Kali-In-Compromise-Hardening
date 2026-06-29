# Firstboot release receipt handoff digest smoke index

`firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py` is a passive, aggregate-only evidence helper for the firstboot release-gate chain. It reads the quoted `.summary.env` output from `firstboot_final_readiness_release_receipt_handoff_digest_smoke.py` and emits JSON, Markdown, and optional summary evidence that indexes the expected smoke artifacts for operator review.

## Purpose

The helper gives release reviewers a compact handoff checkpoint after the release-receipt handoff digest smoke gate. It validates that the previous smoke layer reported a pass decision, no blockers, aggregate-only privacy scope, and enough upstream artifacts to be useful before a hardened image is promoted.

This aligns with secure-by-default control evidence patterns from NIST SP 800-53 control families for auditability, configuration management, system integrity, and least-privilege operations. It also keeps the Kali ISO customization path additive by packaging a helper into the existing `/install` module set rather than changing installation behavior.

## Inputs

Default input:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke.summary.env
```

Required quoted keys:

```text
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_STATUS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_BLOCKERS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_WARNINGS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_ARTIFACTS
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_PRIVACY_SCOPE
```

The parser does not source shell content. Malformed lines are ignored and reported as warnings.

## Outputs

Default JSON output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.json
```

Default summary output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.summary.env
```

Markdown output is available with `--format markdown` and is wired by `firstboot_release_gate.service` to:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.md
```

## Decision contract

The index reports `pass` only when:

- the upstream smoke status is `pass`;
- the upstream smoke blocker count is zero;
- the privacy scope is `aggregate_metadata_only`;
- the upstream smoke artifact count meets the expected floor; and
- all required summary keys parse as non-negative integers where expected.

Any failure returns a review status in the output. Operators can use `--require-pass` to make review status exit non-zero in stricter local release scripts.

## Threat-model rationale

This helper is intentionally passive. It does not open sockets, collect credentials, inspect raw packets, alter firewall rules, mutate systemd state, approve restores, write IDS models or datasets, or change host or VM configuration. Its role is to make formatting-sensitive firstboot evidence failures visible before branch promotion, ISO publishing, or recovery handoff.

## Systemd and packaging integration

`build_custom_iso.sh` packages the helper beside the existing firstboot release-gate modules. `firstboot_release_gate.service` appends JSON and Markdown `ExecStartPost=` steps after the handoff digest smoke artifacts are created.

The existing service sandbox remains in place with `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`, kernel/control-group protections, an empty capability bounding set, read-only evidence inputs, and `/var/log` as the only write path for generated evidence.

## Rollback

To roll this helper back:

1. Remove `firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py` from `build_custom_iso.sh`.
2. Remove the two handoff digest smoke index `ExecStartPost=` lines from `firstboot_release_gate.service`.
3. Delete generated `/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.*` artifacts.

No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.

## Known limitations

This indexes and validates only the aggregate smoke summary contract. It does not replace repository CI, required checks, review-thread resolution, branch protection, manual review of upstream JSON/Markdown artifacts, or stacked PR dependency verification.

## Follow-up work

Feed this summary into a future operator dashboard or aggregate posture report once the final-readiness handoff chain stabilizes.
