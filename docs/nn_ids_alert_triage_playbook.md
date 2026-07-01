# NN IDS Alert Triage Playbook

This playbook gives operators a privacy-safe, defensive handoff path for NN IDS release-readiness, model-card, drift, health, and posture-bundle evidence. It is intentionally passive: it explains how to interpret aggregate artifacts and choose review actions without reading packets, payloads, raw telemetry, secrets, live host state, VM state, or hypervisor state.

## Scope and safety boundary

Use this playbook for defensive review, release gates, firstboot handoffs, and recovery planning. It does not authorize operational targeting, persistence, evasion, live scanning, packet inspection, credential collection, service mutation, firewall mutation, restore execution, retraining, or automated blocking.

Safe defaults:

- Treat all IDS outputs as analytical estimates, not certainty.
- Prefer `watch` and `manual_review` when evidence is incomplete or stale.
- Keep raw telemetry out of release receipts and dashboards.
- Require explicit human approval before any live-state action.
- Preserve rollback notes and artifact hashes with every handoff.

## Inputs

Expected aggregate-only evidence families:

- `nn_ids_health_evidence.json`: model freshness, metric thresholds, and service-health markers.
- `nn_ids_drift_evidence.json`: feature drift, missing-rate, and population-shift evidence.
- `nn_ids_drift_triage.{json,md}`: reviewer-facing drift summary and recommended actions.
- `nn_ids_posture_bundle_manifest.{json,md}`: posture evidence inventory and release blockers.
- `nn_ids_model_card.{json,md}`: model-card release context, freshness, and privacy notes.
- `nn_ids_release_readiness_summary.json`: compact release decision and blocker list.
- `nn_ids_release_readiness_summary.report`: dashboard-safe `key=value` release summary.

Do not paste raw packet captures, model training rows, payload snippets, host secrets, API tokens, endpoint identifiers, or unredacted user data into the triage record.

## Severity bands

| Band | Meaning | Default action |
| --- | --- | --- |
| `pass` | Aggregate evidence is fresh, passive, and release-ready. | Approve the evidence for the current release gate after human review. |
| `watch` | Evidence is acceptable for release but needs closer review, more samples, or follow-up tracking. | Keep release gated to manual review, capture follow-up owner, and re-check freshness. |
| `degraded` | Metrics, health, or drift evidence has concerning findings but no approved live action. | Block promotion until the owner explains impact, rollback, and next evidence needed. |
| `blocked` | Evidence is missing, malformed, stale, unsafe, or requests `retrain`/`restore`. | Fail closed; do not release or automate remediation from this artifact alone. |

## Decision matrix

| Evidence condition | Triage decision | Required handoff note |
| --- | --- | --- |
| Release summary says `ids_release_ready=true`, gate decision is `accept`, and blockers are empty. | `pass` | Record artifact hashes, hosted check names, and reviewer sign-off. |
| Release summary is ready but gate decision is `watch`. | `watch` | Explain what must be observed next and when freshness must be checked again. |
| Drift evidence exceeds threshold or lists shifted features. | `degraded` | Record shifted feature names, threshold context, and privacy-safe validation plan. |
| Health evidence shows stale model, missing metrics, or service-health marker gaps. | `degraded` | Record missing artifact, age, or marker and assign a follow-up owner. |
| Any artifact is missing, malformed, stale beyond policy, or contains raw telemetry/secrets. | `blocked` | Record the exact missing or unsafe evidence and rollback-safe remediation path. |
| Any artifact requests `retrain`, `restore`, auto actions, firewall changes, or service mutation. | `blocked` | Require a separate reviewed change or manual operations ticket before live action. |

## Triage record template

```text
triage_decision=<pass|watch|degraded|blocked>
release_ready=<true|false>
source_artifacts=<comma-separated aggregate artifacts>
artifact_hashes=<sha256 entries or manifest reference>
blocking_issues=<none or concise blocker summary>
uncertainty_note=<why this remains an estimate>
privacy_scope=<aggregate-only; no raw telemetry or secrets>
human_review_required=true
live_action_authorized=false
rollback_reference=<docs/runbook or PR rollback notes>
next_evidence_needed=<freshness recheck, model card, drift review, or hosted gate>
owner=<review role or team>
```

## Operator workflow

1. Confirm the evidence is aggregate-only and safe to publish.
2. Compare the release summary decision to the model card, health evidence, and drift triage.
3. Check artifact age and hashes from the posture bundle or release receipt.
4. Choose the most conservative severity band that matches the evidence.
5. Capture uncertainty and required follow-up in the triage record.
6. Do not run live remediation from triage output; open a separate reviewed change for live-state work.
7. Attach the triage record to the PR, release receipt, firstboot handoff, or recovery bundle.

## Release gate usage

A release gate may consume the triage record only as evidence. It should not source it as shell, execute values from it, or treat it as permission for live action. Gate logic should fail closed when:

- the triage record is missing;
- the triage record is malformed;
- the privacy scope is not aggregate-only;
- `human_review_required` is absent or false;
- `live_action_authorized` is true;
- source artifacts are stale or missing hashes;
- the decision is `degraded` or `blocked`.

## Accessibility and handoff guidance

Keep Markdown summaries short, structured, and screen-reader friendly. Prefer plain severity labels, concrete blocker names, and explicit next steps over dense prose. Avoid color-only status communication. Keep the key/value template stable so dashboards and shell-safe validators can parse it without depending on visual formatting.

## Compatibility

This playbook is documentation-only and additive. Existing IDS helpers, schemas, tests, services, timers, packaging, firstboot workflows, host/VM policy controls, restore gates, and release receipts remain unchanged.

## Rollback

Rollback is a normal revert of this playbook, its static documentation test, and changelog notes. No host, VM, service, firewall, IDS model, dataset, telemetry, secret, package, hypervisor, firstboot, restore, or runtime state requires rollback.

## Follow-up

- Add a passive triage-record schema once the repository standardizes key/value receipt schemas.
- Wire a static triage-record validator into hosted release gates after existing release summary and posture bundle artifacts are published in a shared workspace.
- Add example passing, watch, degraded, and blocked triage records with synthetic evidence only.
