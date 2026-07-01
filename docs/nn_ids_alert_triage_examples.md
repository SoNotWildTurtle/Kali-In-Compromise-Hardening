# NN IDS Alert Triage Examples

These examples show passive, synthetic triage records for the NN IDS alert triage playbook. They are designed for release receipts, firstboot handoffs, recovery bundles, and reviewer training without exposing raw telemetry, packet captures, secrets, host identifiers, VM identifiers, endpoint names, or operational targeting data.

All records preserve the same safety boundary:

- aggregate-only evidence;
- analytical estimates, not certainty;
- `human_review_required=true`;
- `live_action_authorized=false`;
- no remediation, restore, retrain, firewall, service, or hypervisor action from the record alone.

## Example: pass

Use `pass` when aggregate artifacts are present, fresh, hash-referenced, privacy-safe, and aligned with a release-ready summary.

```text
triage_decision=pass
release_ready=true
source_artifacts=nn_ids_release_readiness_summary.json,nn_ids_health_evidence.json,nn_ids_drift_evidence.json,nn_ids_model_card.md,nn_ids_posture_bundle_manifest.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none
uncertainty_note=aggregate metrics look release-ready, but this remains an analytical estimate that requires reviewer sign-off
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=confirm hosted release-gate checks remain green at merge time
owner=release-reviewer
```

Reviewer notes:

- Confirm artifact hashes match the posture bundle.
- Confirm hosted checks are green on the final head SHA.
- Confirm the release summary does not request live remediation.

## Example: watch

Use `watch` when artifacts are usable but need freshness follow-up, more samples, or a specific owner before promotion.

```text
triage_decision=watch
release_ready=true
source_artifacts=nn_ids_release_readiness_summary.report,nn_ids_health_evidence.json,nn_ids_model_card.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=none; freshness recheck required before next release
uncertainty_note=health evidence is acceptable for this handoff, but sample age increases uncertainty
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=fresh drift triage and model-card age check before promotion
owner=ids-maintainer
```

Reviewer notes:

- Keep the release path manual until the freshness check is attached.
- Record the next evidence deadline in the PR or handoff ticket.
- Do not change service, firewall, restore, or retrain state from this record.

## Example: degraded

Use `degraded` when aggregate evidence indicates concerning drift, missing metrics, stale model context, or service-health gaps that should block promotion until explained.

```text
triage_decision=degraded
release_ready=false
source_artifacts=nn_ids_drift_evidence.json,nn_ids_drift_triage.md,nn_ids_health_evidence.json
artifact_hashes=manifest:nn_ids_posture_bundle_manifest.json#sha256
blocking_issues=drift evidence exceeds threshold for synthetic_feature_group_alpha; health evidence missing latest model-card freshness marker
uncertainty_note=drift and health signals are aggregate-only indicators and need reviewed validation before any live-state response
privacy_scope=aggregate-only; no raw telemetry or secrets
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=privacy-safe drift explanation, model-card refresh, and rerun of hosted release gate
owner=model-reviewer
```

Reviewer notes:

- Block promotion until the missing model-card marker is fixed or justified.
- Attach a privacy-safe drift explanation and focused validation command.
- Open a separate reviewed change for any model, restore, retrain, or deployment action.

## Example: blocked

Use `blocked` when evidence is missing, malformed, unsafe, stale beyond policy, or attempts to cross from passive evidence into runtime-state change territory.

```text
triage_decision=blocked
release_ready=false
source_artifacts=nn_ids_release_readiness_summary.json,nn_ids_posture_bundle_manifest.json
artifact_hashes=missing manifest hash for nn_ids_release_readiness_summary.json
blocking_issues=release summary is malformed and attempts to cross from passive evidence into runtime-state change territory; posture bundle lacks required artifact hash
uncertainty_note=unsafe or malformed aggregate evidence prevents a reliable analytical estimate
privacy_scope=aggregate-only required; record rejected because safety boundary could not be verified
human_review_required=true
live_action_authorized=false
rollback_reference=docs/nn_ids_alert_triage_playbook.md#rollback
next_evidence_needed=regenerate aggregate-only release summary, publish hashes, and rerun static release-gate validation
owner=release-owner
```

Reviewer notes:

- Fail closed and leave the PR or release blocked.
- Remove or replace malformed evidence with aggregate-only artifacts.
- Require a separate reviewed operations path before any runtime-state change.

## Accessibility and handoff notes

- Keep each record in stable `key=value` form so shell-safe validators can parse it.
- Use plain severity words instead of emoji or color-only labels.
- Keep blocker text concise and specific.
- Prefer synthetic feature names in public examples.
- Include rollback references even when no runtime state changed.

## Compatibility and rollback

These examples are documentation-only. They do not change NN IDS services, timers, packaging, firstboot wiring, host/VM isolation controls, restore gates, telemetry collection, model training, firewall rules, or runtime state.

Rollback is a normal revert of this examples document, its changelog fragment, and its static documentation test. No host, VM, IDS model, dataset, service, firewall, hypervisor, firstboot, restore, package, secret, or runtime state requires rollback.

## Follow-up work

- Convert the example records into fixture files once a passive triage-record schema exists.
- Add a dependency-free validator that rejects malformed or unsafe triage records.
- Wire the validator into hosted release gates after release summary and posture bundle artifacts are available in a shared workspace.