# Changelog Fragment: Host/VM Policy Manifest Evidence

## Added

- Added `--manifest-output` to `host_vm_policy_validator.py` so passive policy checks can write a compact JSON manifest alongside JSON or Markdown evidence.
- Added validator version metadata and profile SHA-256 evidence to the validator output.
- Added manifest regression coverage for profile hashing, evidence-path traceability, passive safety flags, and handoff rollback notes.
- Updated `docs/host_vm_policy_validator_cli.md` with manifest usage guidance.

## Security

- Manifest output is aggregate-only metadata that records which profile produced which evidence file.
- The manifest does not read raw telemetry, inspect live host or VM state, alter firewall rules, manage services, open sockets, install packages, store credentials, mutate approval state, mutate restore state, or change IDS artifacts.
- Rollback remains file-only: remove the generated manifest/evidence files or revert this changelog, documentation, test, and validator update.

## Compatibility

- `--manifest-output` is optional.
- Existing stdout, `--format`, and `--output` behavior remains compatible for current examples, tests, and operator workflows.
- The validator continues to use only Python standard-library modules.

## Follow-up

- Add a passive firstboot dry-run wrapper that writes validator evidence and manifest files under controlled paths.
- Add release-gate aggregation that consumes manifest JSON only after the aggregator has static coverage and privacy-boundary tests.
