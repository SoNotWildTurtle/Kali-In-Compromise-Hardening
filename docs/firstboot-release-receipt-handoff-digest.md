# Firstboot final-readiness release receipt handoff digest

`firstboot_final_readiness_release_receipt_handoff_digest.py` is a passive operator digest helper for the firstboot final-readiness release receipt smoke-index `.summary.env` sidecar. It gives release reviewers a compact handoff artifact map and promotion checklist after the release receipt, smoke helper, and smoke index have all run.

## Purpose

The helper validates that the smoke-index summary includes the expected quoted keys, reports `pass`, carries zero blockers, preserves the `aggregate_metadata_only` privacy scope, and points at at least the expected aggregate release receipt smoke artifacts. It then emits JSON, Markdown, and `.summary.env` evidence for operator handoff.

It is intentionally passive and aggregate-only. It does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, alter IDS models or datasets, or modify host/VM state.

## Inputs

Default input:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.summary.env
```

Required keys:

```text
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_STATUS="pass"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_BLOCKERS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_ARTIFACTS="3"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_PRIVACY_SCOPE="aggregate_metadata_only"
```

Malformed lines are ignored instead of sourced, and a warning is emitted so reviewers can fix formatting without executing untrusted shell content.

## Outputs

Default JSON output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.json
```

Default summary output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.summary.env
```

Markdown output can be requested with `--format markdown` and is wired by `firstboot_release_gate.service` to:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.md
```

## Release-gate behavior

Use `--require-pass` when a caller needs a non-zero exit code for review/deferred digest evidence. Review status means at least one required smoke-index summary key is missing, a count is malformed, the upstream smoke-index status is not `pass`, smoke-index blockers are present, privacy scope is not aggregate-only, or the artifact count is below the expected release receipt smoke evidence floor.

## Threat-model rationale

This layer catches formatting-sensitive or contract-breaking smoke-index summary regressions before an image promotion handoff. It deliberately validates only the small smoke-index summary contract and provides pointers to aggregate artifacts plus a human promotion checklist. It does not recompute upstream evidence, make trust decisions about raw logs, or perform remediation. That keeps failures auditable, reversible, least-privilege, and safe by default.

## Rollback

Remove `firstboot_final_readiness_release_receipt_handoff_digest.py` from `build_custom_iso.sh`, remove the handoff digest `ExecStartPost=` lines from `firstboot_release_gate.service`, and delete generated `/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.*` artifacts. No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.

## Known limitations

The helper validates summary evidence only. Operators should still review the upstream release receipt, smoke, and smoke-index JSON/Markdown artifacts, repository checks, review threads, branch protection, and stacked dependency order before publishing or merging.

## Follow-up work

Feed the digest summary into a future operator dashboard or aggregate posture gate after the firstboot evidence contract stabilizes.
