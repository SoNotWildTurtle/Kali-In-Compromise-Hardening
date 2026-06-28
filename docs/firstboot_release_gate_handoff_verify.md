# Firstboot release-gate handoff verification

`firstboot_release_gate_handoff_verify.py` is a passive helper for release review, recovery bundle checks, and operator handoff. It reads an existing `firstboot_release_gate.handoff_index.json`, rechecks required artifact presence, recomputes SHA-256 hashes, and emits JSON or Markdown verification evidence.

## Usage

```bash
firstboot_release_gate_handoff_verify.py \
  --index /var/log/firstboot_release_gate.handoff_index.json \
  --output /var/log/firstboot_release_gate.handoff_verify.json

firstboot_release_gate_handoff_verify.py \
  --index ./handoff/firstboot_release_gate.handoff_index.json \
  --artifact-root ./handoff \
  --format markdown \
  --output ./handoff/firstboot_release_gate.handoff_verify.md

firstboot_release_gate_handoff_verify.py \
  --require-verified \
  --index ./handoff/firstboot_release_gate.handoff_index.json \
  --artifact-root ./handoff
```

`--artifact-root` lets reviewers verify a copied handoff directory using artifact basenames from the index. Without it, the verifier uses recorded paths when present and otherwise falls back to the index directory.

Custom ISO builds package the verifier by default. `firstboot_release_gate.service` refreshes both `/var/log/firstboot_release_gate.handoff_verify.json` and `/var/log/firstboot_release_gate.handoff_verify.md` after the handoff index is generated, using `/var/log` as the artifact root so operators get immediate aggregate verification evidence for the current firstboot evidence set.

## Output contract

The JSON output contains:

- `schema_version` and `component` for machine-readable consumers.
- `decision` and `release_gate`, using `approved/pass` only when the handoff index is approved and all indexed evidence verifies.
- `artifact_counts` with total, required, required verified, hashed, and hash-verified counts.
- `artifacts` with expected and actual size/hash values plus a per-artifact `verified` flag.
- `blockers` for missing index files, malformed JSON, privacy-scope mismatches, deferred handoff indexes, missing artifacts, size mismatches, hash mismatches, and missing expected hashes.
- `manager_summary`, `handoff_checklist`, `privacy_scope`, `privacy_exclusions`, `safe_default`, and `rollback_note`.

The Markdown output renders the same aggregate evidence for operator or manager review without requiring JSON tooling.

## Threat-model rationale

This helper is intentionally read-only and aggregate-only. It does not inspect raw logs, packets, captures, credentials, hostnames, usernames, secrets, model binaries, datasets, environment identifiers, live services, firewall state, host settings, VM settings, approval state, restore state, or firstboot state.

It verifies that the privacy-safe handoff artifacts copied into a release or recovery bundle still match the previously generated SHA-256 values. That supports reproducibility, handoff confidence, and fail-closed review without adding new control-plane behavior.

The service integration remains passive: it writes derived verification artifacts only, keeps the existing systemd sandbox posture, does not request capabilities, and does not alter network, firewall, host, VM, IDS, approval, restore, or firstboot state.

## Compatibility

This is additive. Existing release-gate, status, bundle manifest, operator digest, and handoff index schemas remain unchanged. Consumers that do not need independent bundle verification can ignore this helper.

## Rollback

Delete the generated `firstboot_release_gate.handoff_verify.json` or `.md` artifact, or revert the helper, docs, tests, packaging entry, and two `ExecStartPost` service lines. The upstream firstboot release gate, status, bundle manifest, operator digest, and handoff index remain unchanged.

## Follow-up work

- Add optional freshness checks for copied handoff bundles when release policy requires strict age thresholds.
- Add release workflow integration that runs `--require-verified` against promoted handoff archives.
- Add dashboard support that displays verification blockers alongside the handoff index.
