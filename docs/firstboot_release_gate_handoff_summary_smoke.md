# Firstboot release-gate handoff summary smoke check

`firstboot_release_gate_handoff_summary_smoke.py` is a passive reader for the shell-friendly handoff freshness `.summary.env` artifact. It gives CI jobs, release scripts, firstboot smoke checks, and operator dashboards a small machine-readable signal without requiring them to parse the authoritative freshness JSON.

The helper is intentionally narrow: it validates aggregate-only key/value evidence, catches contradictory status combinations, and emits JSON or Markdown smoke evidence for promotion review.

## Usage

```bash
python3 firstboot_release_gate_handoff_summary_smoke.py \
  --input /var/log/firstboot_release_gate.handoff_freshness.summary.env \
  --output /var/log/firstboot_release_gate.handoff_summary_smoke.json \
  --require-pass
```

Markdown output is available for human handoff notes:

```bash
python3 firstboot_release_gate_handoff_summary_smoke.py \
  --input /var/log/firstboot_release_gate.handoff_freshness.summary.env \
  --output /var/log/firstboot_release_gate.handoff_summary_smoke.md \
  --format markdown
```

When `--require-pass` is set, the helper exits non-zero unless the summary is present, complete, internally consistent, marked approved, and has a passing release gate.

## Output contract

The JSON output includes:

- `component`: always `firstboot_release_gate_handoff_summary_smoke`.
- `decision`: `approved` or `deferred`.
- `release_gate`: `pass` or `stop`.
- `source_component`, `source_created_utc`, and `source_input` copied from aggregate freshness summary fields.
- `source_values`: parsed aggregate status, gate, blocker count, artifact count, freshness count, and freshness policy values.
- `blockers`: machine-readable reasons that must be fixed before promotion.
- `operator_next_steps`: privacy-safe remediation guidance.
- `privacy_scope`: always `aggregate_release_gate_handoff_summary_smoke_only`.

The helper expects the upstream summary fields produced by `firstboot_release_gate_handoff_freshness.py`, including:

- `FIRSTBOOT_HANDOFF_FRESHNESS_OK`
- `FIRSTBOOT_HANDOFF_FRESHNESS_DECISION`
- `FIRSTBOOT_HANDOFF_FRESHNESS_RELEASE_GATE`
- `FIRSTBOOT_HANDOFF_FRESHNESS_BLOCKER_COUNT`
- `FIRSTBOOT_HANDOFF_FRESHNESS_BLOCKERS`
- `FIRSTBOOT_HANDOFF_FRESHNESS_PRIVACY_SCOPE`

## Threat-model rationale

The full handoff freshness JSON remains authoritative, but lightweight release tooling often needs a fast, shell-friendly gate. This helper reduces brittle ad hoc parsing by validating the summary schema, type expectations, privacy scope, and consistency rules before treating a handoff as passed.

This follows the repository's additive evidence direction and aligns with continuous-monitoring guidance that favors repeatable, machine-readable status evidence for security control assessment. It also supports least-privilege release automation because consumers can read aggregate-only status instead of broader JSON evidence.

## Privacy and safety

The helper is read-only. It does not open network sockets, execute host commands, restart services, change firewall rules, touch model files, update datasets, approve restore actions, or modify firstboot state.

The smoke output is aggregate-only. It does not include raw logs, packet contents, captures, credentials, hostnames, usernames, secrets, model binaries, datasets, environment identifiers, or remediation payloads from upstream systems.

## Compatibility

The helper uses only the Python standard library and works with Python 3 on Kali/Debian-like systems. It is packaged into the custom ISO by `build_custom_iso.sh` and refreshed by `firstboot_release_gate.service` after the freshness summary exists.

## Rollback

Rollback is additive and low risk:

1. Remove the smoke-check `ExecStartPost=` lines from `firstboot_release_gate.service`.
2. Stop calling `firstboot_release_gate_handoff_summary_smoke.py` from CI, firstboot, or release review scripts.
3. Delete generated `/var/log/firstboot_release_gate.handoff_summary_smoke.json` and `/var/log/firstboot_release_gate.handoff_summary_smoke.md` artifacts if desired.
4. Revert this helper, docs, packaging entry, service wiring, and tests.

Upstream firstboot release-gate, handoff verification, freshness JSON, freshness Markdown, and `.summary.env` artifacts are never modified by this helper.

## Follow-up work

- Feed the smoke JSON into future aggregate posture dashboards.
- Add a release workflow step that archives smoke JSON beside the authoritative freshness evidence.
- Add a tiny terminal/status reader that displays only the smoke result for operators during ISO promotion.
