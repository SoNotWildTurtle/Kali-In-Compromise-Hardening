# Firstboot release-gate handoff freshness

`firstboot_release_gate_handoff_freshness.py` is a passive helper for release review, recovery bundle checks, and operator handoff. It reads an existing `firstboot_release_gate.handoff_verify.json`, checks the verification artifact and verified required aggregate artifacts against an age threshold, and emits JSON or Markdown freshness evidence.

## Usage

```bash
firstboot_release_gate_handoff_freshness.py \
  --input /var/log/firstboot_release_gate.handoff_verify.json \
  --output /var/log/firstboot_release_gate.handoff_freshness.json

firstboot_release_gate_handoff_freshness.py \
  --input ./handoff/firstboot_release_gate.handoff_verify.json \
  --format markdown \
  --max-artifact-age-minutes 240 \
  --output ./handoff/firstboot_release_gate.handoff_freshness.md

firstboot_release_gate_handoff_freshness.py \
  --require-fresh \
  --max-artifact-age-minutes 60 \
  --input ./handoff/firstboot_release_gate.handoff_verify.json
```

The default policy allows evidence up to 1440 minutes old. Release, recovery, or firstboot workflows can set a shorter `--max-artifact-age-minutes` window when promoted evidence must be recent.

## Firstboot service integration

Custom ISO builds now package the helper alongside the firstboot release-gate bundle tools. `firstboot_release_gate.service` refreshes both artifacts after handoff verification succeeds:

- `/var/log/firstboot_release_gate.handoff_freshness.json`
- `/var/log/firstboot_release_gate.handoff_freshness.md`

The service uses the same 240-minute policy window as the release gate timer path so operator handoff bundles can detect stale copied evidence without reading raw telemetry, opening sockets, changing firewall rules, approving restores, modifying IDS models, or altering host/VM state.

## Output contract

The JSON output contains:

- `schema_version` and `component` for machine-readable consumers.
- `decision` and `release_gate`, using `approved/pass` only when handoff verification is approved and all verified required artifacts are fresh.
- `freshness_policy` with the threshold and evaluator clock.
- `verification_artifact` with mtime, age, and freshness for the handoff verification JSON.
- `artifact_counts` with total verified artifacts and fresh verified required artifacts.
- `artifacts` with per-artifact required/verified/existence/freshness fields.
- `blockers` for missing input, malformed JSON, component or privacy-scope mismatch, deferred verification, stale verification evidence, missing verified artifacts, stale verified artifacts, and invalid freshness thresholds.
- `manager_summary`, `handoff_checklist`, `privacy_scope`, `privacy_exclusions`, `safe_default`, and `rollback_note`.

Markdown output renders the same aggregate-only evidence for operator or manager review without requiring JSON tooling.

## Threat-model rationale

This helper is intentionally read-only and aggregate-only. It does not inspect raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, datasets, environment identifiers, live services, firewall state, host settings, VM settings, approval state, restore state, network state, or firstboot state.

Freshness gating helps prevent stale copied handoff bundles from being treated as current approval evidence. The helper complements hash verification by requiring the already verified aggregate evidence set to be recent enough for the release, recovery, or manager-handoff policy.

## Compatibility

This is additive. Existing release-gate, status, bundle manifest, operator digest, handoff index, and handoff verification schemas remain unchanged. Consumers that do not need strict freshness evidence can ignore this helper. Existing custom ISO build arguments remain unchanged; the helper is simply included in the packaged firstboot tool set.

## Rollback

Delete the generated `firstboot_release_gate.handoff_freshness.json` or `.md` artifact, or revert this additive helper, docs, changelog, service wiring, packaging entry, and tests. The upstream firstboot release gate, status, bundle manifest, operator digest, handoff index, and handoff verification remain unchanged.

## Follow-up work

- Add release workflow integration that runs `--require-fresh` against promoted handoff archives.
- Feed freshness decision fields into any aggregate posture dashboard or release-promotion checklist.
