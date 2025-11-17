# Recommendations

## R1. Harden SSH access-control automation and monitoring
- Status: In progress
  - [x] Validate SSH whitelist and blacklist integrity inside the health check, including iptables enforcement and secure path checks.
  - [x] Surface SSH access diagnostics in the dashboard for rapid operator triage and remote/console review.
  - [ ] Automate refresh of the ssh_access_control.sh rules after configuration edits from the dashboard.
    - Prototype a privileged helper that can diff staged whitelist updates and safely reload iptables rules.
  - [ ] Add regression tests that exercise whitelist/blacklist edge cases and iptables hook detection.
    - Capture representative allow/deny matrices and simulate rule application inside CI to prevent regressions.

## R2. Expand remote threat intelligence synchronization safeguards
- Status: In progress
  - [x] Add active reachability probes for threat feed endpoints to distinguish remote outages from stale files.
    - Implemented cached HTTP HEAD/GET probes in the health checker and dashboard to confirm endpoint availability and surface outages.
  - [ ] Stage remediation actions that can automatically re-run the blocklist updater with exponential backoff.
    - Plan to reuse the new reachability diagnostics to trigger guarded retries and capture outcomes in the health log.
  - [ ] Mirror the remote reachability telemetry in the dashboard with alerting hooks.
    - Extend the Resilience view with alert thresholds and remote notifications once the probe cadence stabilizes.

## R3. Deepen resource monitor analytics for distributed deployments
- Status: Planned
  - [ ] Aggregate resource monitor spikes across hosts and store daily digests for trend analysis.
    - Introduce a lightweight collector that ships summaries to a central aggregator without overwhelming bandwidth.
  - [ ] Teach the dashboard to compare local resource readings against remote peers for anomaly detection.
    - Add diff visualizations with percentile overlays so outliers stand out during remote reviews.
  - [ ] Add export routines so remote operators can pull structured resource anomalies via API.
    - Mirror existing CSV exports with JSON endpoints to simplify automation scripts.

## R4. Automate baseline drift detection for process and port monitors
- Status: Planned
  - [ ] Build background jobs that snapshot baseline hashes and alert on drift without requiring manual health runs.
    - Leverage systemd timers to capture hashes hourly and send drift alerts into the health log stream.
  - [ ] Extend the dashboard with delta visualizations between stored baselines and live inventory.
    - Render before/after tables and highlight new or missing entries for quick operator triage.
  - [ ] Provide remediation scripts that can roll back to last-known-good baselines in a single action.
    - Bundle rollback scripts with integrity checks to avoid reinstalling corrupted baselines.

## R5. Strengthen snapshot validation and recovery drills
- Status: Planned
  - [ ] Schedule periodic automated restore simulations that verify backups boot and services start.
    - Spin up disposable containers or VMs to rehearse restores and capture verification logs.
  - [ ] Capture remote storage latency metrics to warn about slow snapshot replication.
    - Track latency deltas across storage tiers and feed them into the resilience dashboard.
  - [ ] Add dashboard tasks that orchestrate remote/local restore dry runs with logging.
    - Provide guided wizards that document each restore step for later audits.

## R6. Enhance compliance reporting and audit exports
- Status: Planned
  - [ ] Generate consolidated compliance reports from health check results for remote auditors.
    - Convert health logs into signed PDF/HTML bundles that auditors can review offline.
  - [ ] Add CLI hooks to push audit bundles to secure remote storage.
    - Support SFTP and HTTPS transports with configurable credentials and retries.
  - [ ] Surface compliance posture summaries inside the dashboard with export shortcuts.
    - Embed quick-export buttons and mention report cadence within maintenance guidance.

## R7. Expand remote diagnostics APIs for automation tooling
- Status: Planned
  - [ ] Expose a machine-readable health endpoint that streams recent probe outcomes and remediation guidance.
    - Design a minimal JSON schema compatible with remote SOAR ingestion and include endpoint reachability verdicts.
  - [ ] Provide authenticated webhook triggers for critical degradations so remote operators can subscribe to alerts.
    - Reuse existing logging facilities to batch notifications and guard against repeated flapping events.
  - [ ] Document API usage with curl examples and dashboard quick links for hybrid local/remote workflows.
    - Ensure the documentation includes role-based access patterns and fallback CLI options for air-gapped sites.

## R8. Automate recovery drills across health check modules
- Status: Planned
  - [ ] Schedule synthetic failure injections that validate each mitigation path without impacting production data.
    - Leverage tmpfs sandboxes to rehearse logrotate, threat feed, and monitor recovery without touching live files.
  - [ ] Capture drill telemetry inside the dashboard with pass/fail histories and timestamps.
    - Store drill history alongside existing resilience panels and annotate the most recent execution window.
  - [ ] Integrate automated rollback scripts that operators can trigger after a failed drill review.
    - Bundle rollback scripts with dry-run options and logging to align with compliance and change management needs.

## R9. Strengthen observability for system resource regressions
- Status: Planned
  - [ ] Add structured metrics export for CPU, memory, inode, and disk checks to feed external monitoring stacks.
    - Emit Prometheus-friendly text or JSON lines and include check thresholds so dashboards can render context.
  - [ ] Implement anomaly detection on recent resource history to preempt slow-burning capacity issues.
    - Train lightweight baselines on historical health logs and surface deviations within the dashboard overview.
  - [ ] Provide guided remediation playbooks linked from each resource warning inside the GUI.
    - Curate step-by-step runbooks with CLI snippets and remote execution notes for distributed operators.

## R10. Harden alert reporting pipeline and notification hygiene
- Status: In progress
  - [x] Add health check coverage for alert report state, log, and timers with hourly drift detection.
    - Integrated `check_alert_reporting` to validate state cursors, log freshness, and systemd scheduling.
  - [x] Surface alert reporting diagnostics across the dashboard maintenance and resilience views.
    - Added analyzer coverage, quick actions, and filesystem hygiene tracking for alert reporting assets.
  - [ ] Automate delivery of alert summary exports for remote review workflows.
    - Generate signed JSON bundles of hourly summaries and publish via the upcoming diagnostics API.
  - [ ] Provide a CLI drill that seeds synthetic alerts to validate reporting end-to-end.
    - Replay captured packets through nn_ids_report.service and compare resulting report deltas automatically.

## R11. Expose remote webhook notifications for critical degradations
- Status: Planned
  - [ ] Stand up an authenticated webhook dispatcher that streams health failures to subscribed endpoints.
    - Reuse cached reachability probes and throttle repeats to protect downstream automation.
  - [ ] Document webhook payload schemas with example cURL invocations for remote SOC tooling.
    - Include signatures, retry semantics, and mapping back to dashboard remediation guidance.
  - [ ] Add dashboard controls to manage webhook subscriptions and simulate test alerts.
    - Provide UI toggles and dry-run buttons so operators can verify integrations without downtime.

## R12. Automate incident-ready alert enrichment
- Status: Planned
  - [ ] Attach GeoIP, ASN, and reputation lookups to hourly alert summaries before notifications fire.
    - Cache enrichment datasets locally and annotate nn_ids_report outputs with contextual metadata.
  - [ ] Extend the dashboard to visualize enriched alert history with filterable pivots.
    - Provide per-country and per-provider aggregations for remote analysts.
  - [ ] Ship enrichment deltas to the recommendations tracker to capture emerging hotspots.
    - Write automation that files follow-up tasks whenever high-risk providers repeatedly appear.

## R13. Expand autonomous recovery tooling for notification failures
- Status: Planned
  - [ ] Implement watchdog jobs that restart nn_ids_report units when state freshness thresholds are exceeded.
    - Track restart outcomes and annotate them within the health log for later review.
  - [ ] Capture automatic post-restart validation that confirms new report entries landed successfully.
    - Compare state cursors and tail logs before and after restarts to confirm remediation worked.
  - [ ] Provide guided rollback scripts to restore previous state snapshots if corruption is detected.
    - Bundle rollback tooling with dry-run and checksum verification options for safe recovery.

## R14. Assure time synchronization integrity across deployments
- Status: In progress
  - [x] Integrate timedatectl and chronyc telemetry into the health checker and dashboard for automated drift detection.
    - Added backend validation plus UI diagnostics so operators can review clock status locally or remotely.
  - [ ] Stream time synchronization metrics through the planned diagnostics API for remote automation.
    - Publish current offsets, last sync timestamps, and active peers alongside remediation hints.
  - [ ] Automate guarded restart routines for chronyd/timesyncd when drift thresholds are breached.
    - Provide dry-run logging and rollback hooks to avoid destabilizing production clocks.

## R15. Harden remote communications and certificate lifecycle
- Status: Planned
  - [ ] Audit TLS configurations for IDS webhooks, feeds, and automation endpoints.
    - Capture cipher, protocol, and expiry details inside the health log for rapid remediation.
  - [ ] Implement certificate expiry alerts in both CLI and dashboard views.
    - Surface 30/14/7-day countdowns with quick actions to renew or rotate credentials.
  - [ ] Stage automated certificate renewal playbooks for hybrid deployments.
    - Provide scripted ACME and offline renewal flows with verification checkpoints.

## R16. Expand firmware and hardware attestation coverage
- Status: Planned
  - [ ] Integrate TPM/secure boot state checks into the health report.
    - Detect disabled secure boot or mismatched PCR values before adversaries exploit hardware gaps.
  - [ ] Surface BIOS/firmware version drift in the dashboard with vendor baseline comparisons.
    - Track last-audit timestamps and flag devices requiring on-site intervention.
  - [ ] Automate evidence collection for remote auditors reviewing hardware integrity.
    - Bundle signed attestation blobs with recommendations exports for compliance teams.
