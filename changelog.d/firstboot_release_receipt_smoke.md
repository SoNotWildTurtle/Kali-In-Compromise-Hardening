# Firstboot release receipt smoke evidence

## Added

- Added `firstboot_final_readiness_release_receipt_smoke.py`, a passive aggregate-only smoke gate for the release receipt `.summary.env` sidecar that validates quoted `FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_*` fields without sourcing shell content.
- Packaged the release receipt smoke helper, wired `firstboot_release_gate.service` to refresh JSON, Markdown, and `.summary.env` smoke artifacts, and documented approval, rollback, privacy, safe-default behavior, and static coverage.

## Security

- The release receipt smoke helper is additive and passive: it validates only the quoted aggregate release receipt summary sidecar, emits derived smoke evidence, and does not source shell content, inspect raw telemetry, open sockets, change firewall rules, mutate services, approve restores, alter IDS models or datasets, or modify host/VM state.
- The `--require-pass` path exits non-zero when release receipt summary evidence is missing, malformed, privacy-scope mismatched, blocker-inconsistent, artifact-empty, or not approved/pass/ready.
