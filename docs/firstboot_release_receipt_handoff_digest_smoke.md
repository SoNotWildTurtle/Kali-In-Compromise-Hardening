# Firstboot release receipt handoff digest smoke

`firstboot_final_readiness_release_receipt_handoff_digest_smoke.py` is a passive smoke-validation helper for the firstboot final-readiness release receipt handoff digest `.summary.env` sidecar.

## Purpose

The helper validates the digest summary contract after the release receipt handoff digest has run. It catches formatting-sensitive regressions before promotion by checking that the digest reports `pass`, has zero blockers, preserves the `aggregate_metadata_only` privacy scope, and advertises at least the expected handoff artifact floor.

It is intentionally aggregate-only and passive. It does not source shell content, open sockets, change firewall rules, mutate services, approve restores, alter IDS models or datasets, or modify host/VM state.

## Inputs

Default input:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.summary.env
```

Required keys:

```text
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_STATUS="pass"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_BLOCKERS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_ARTIFACTS="9"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_PRIVACY_SCOPE="aggregate_metadata_only"
```

Malformed lines are ignored instead of sourced, and a warning is emitted so reviewers can fix formatting without executing untrusted shell content.

## Outputs

Default JSON output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke.json
```

Default summary output:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke.summary.env
```

Markdown output can be requested with `--format markdown` and is wired by `firstboot_release_gate.service` to:

```text
/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke.md
```

## Release-gate behavior

Use `--require-pass` when a caller needs a non-zero exit code for review/deferred smoke evidence. Review status means at least one required digest summary key is missing, a count is malformed, the upstream digest status is not `pass`, digest blockers are present, privacy scope is not aggregate-only, or the artifact count is below the expected handoff artifact floor.

## Threat-model rationale

This layer gives reviewers a small, machine-readable proof that the operator handoff digest summary remained parseable and least-privilege after firstboot release evidence generation. It aligns with auditable control evidence, configuration validation, and safe release-gate workflows without expanding privileges or collecting raw telemetry. NIST SP 800-53 Rev. 5 describes security and privacy controls as flexible, customizable controls implemented through organization-wide risk management, and its 2025 planning note added updates touching audit, authorization monitoring, incident response, supply-chain, and system-integrity relationships. Kali's official ISO guidance also emphasizes build-script-driven customization for live and installer images, so this helper remains packaged through the existing ISO build path.

## Rollback

Remove `firstboot_final_readiness_release_receipt_handoff_digest_smoke.py` from `build_custom_iso.sh`, remove the two handoff digest smoke `ExecStartPost=` lines from `firstboot_release_gate.service`, and delete generated `/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke.*` artifacts. No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.

## Known limitations

The helper validates digest summary evidence only. Operators should still review upstream JSON/Markdown artifacts, repository checks, review threads, branch protection, and stacked dependency order before publishing or merging.

## Follow-up work

Feed the smoke summary into a future operator dashboard or aggregate posture gate after the final-readiness evidence contract stabilizes.
