# Firstboot final-readiness release receipt smoke index

`firstboot_final_readiness_release_receipt_smoke_index.py` is a passive index helper for the firstboot final-readiness release receipt smoke `.summary.env` sidecar. It gives operators, dashboards, and release reviewers a compact artifact map after the smoke helper validates the release receipt contract.

## Purpose

The helper validates that the smoke summary includes the expected quoted keys, reports `pass`, carries zero smoke blockers, and preserves the `aggregate_metadata_only` privacy scope. It then emits a small index that points at the JSON, Markdown, and `.summary.env` smoke artifacts needed for release-review handoff.

It is intentionally passive and aggregate-only. It does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, alter IDS models or datasets, or modify host/VM state.

## Inputs

Default input:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.summary.env
```

Required keys:

```text
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_STATUS="pass"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_BLOCKERS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_PRIVACY_SCOPE="aggregate_metadata_only"
```

Malformed lines are ignored instead of sourced, and a warning is emitted so reviewers can fix formatting without executing untrusted shell content.

## Outputs

Default JSON output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.json
```

Default summary output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.summary.env
```

Markdown output can be requested with `--format markdown` and is wired by `firstboot_release_gate.service` to:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.md
```

## Release-gate behavior

Use `--require-pass` when a caller needs a non-zero exit code for review/deferred index evidence. Review status means at least one required smoke summary key is missing, a count is malformed, the upstream smoke status is not `pass`, smoke blockers are present, or privacy scope is not aggregate-only.

## Threat-model rationale

This layer catches formatting-sensitive or contract-breaking smoke summary regressions before an image promotion handoff. It deliberately validates only the small smoke summary contract and provides pointers to aggregate artifacts. It does not recompute upstream evidence, make trust decisions about raw logs, or perform remediation. That keeps failures auditable, reversible, and safe by default.

## Rollback

Remove `firstboot_final_readiness_release_receipt_smoke_index.py` from `build_custom_iso.sh`, remove the release receipt smoke index `ExecStartPost=` lines from `firstboot_release_gate.service`, and delete generated `/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.*` artifacts. No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.

## Known limitations

The helper validates summary evidence only. Operators should still review the upstream release receipt smoke JSON/Markdown, repository checks, review threads, branch protection, and stacked dependency order before publishing or merging.

## Follow-up work

Feed the smoke index summary into a future operator dashboard or aggregate posture gate after the firstboot evidence contract stabilizes.
