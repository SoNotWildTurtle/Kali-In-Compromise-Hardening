# Firstboot final-readiness release receipt smoke

`firstboot_final_readiness_release_receipt_smoke.py` is a passive smoke validator for the firstboot final-readiness release receipt `.summary.env` sidecar. It gives operators, dashboards, and release reviewers a small machine-readable contract check after the release receipt is generated.

## Purpose

The helper validates that the release receipt summary includes the expected quoted keys, reports an approved/pass/ready status, carries zero blockers, records at least one aggregate artifact, and preserves the `aggregate_metadata_only` privacy scope.

It is intentionally passive and aggregate-only. It does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, alter IDS models or datasets, or modify host/VM state.

## Inputs

Default input:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt.summary.env
```

Required keys:

```text
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_STATUS="approved"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_BLOCKERS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_ARTIFACTS="2"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_PRIVACY_SCOPE="aggregate_metadata_only"
```

Malformed lines are ignored instead of sourced, and a warning is emitted so reviewers can fix formatting without executing untrusted shell content.

## Outputs

Default JSON output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.json
```

Default summary output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.summary.env
```

Markdown output can be requested with `--format markdown` and is wired by `firstboot_release_gate.service` to:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.md
```

## Release-gate behavior

Use `--require-pass` when a caller needs a non-zero exit code for review/deferred smoke evidence. Review status means at least one required summary key is missing, a count is malformed, the upstream release receipt is not approved/pass/ready, blockers are present, no artifacts are reported, or privacy scope is not aggregate-only.

## Threat-model rationale

This layer catches formatting-sensitive or contract-breaking release receipt regressions before an image promotion handoff. It deliberately validates only the small summary contract and does not recompute upstream evidence, make trust decisions about raw logs, or perform remediation. That keeps failures auditable, reversible, and safe by default.

## Rollback

Remove `firstboot_final_readiness_release_receipt_smoke.py` from `build_custom_iso.sh`, remove the release receipt smoke `ExecStartPost=` lines from `firstboot_release_gate.service`, and delete generated `/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.*` artifacts. No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.

## Known limitations

The helper validates summary evidence only. Operators should still review the upstream release receipt JSON/Markdown, repository checks, review threads, branch protection, and stacked dependency order before publishing or merging.

## Follow-up work

Feed the smoke summary into a future operator dashboard or aggregate posture gate after the firstboot evidence contract stabilizes.
