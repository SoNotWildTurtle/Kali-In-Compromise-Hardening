# Kali Neural Defense Press

> Build a hardened Kali Linux image that deploys a self-learning, self-healing intrusion detection platform with automated host defenses and an operator-ready dashboard.

## Table of Contents
- [1. Overview](#1-overview)
- [2. Architecture at a Glance](#2-architecture-at-a-glance)
- [3. Feature Highlights](#3-feature-highlights)
  - [Press Automation](#press-automation)
  - [Neural IDS & Analytics](#neural-ids--analytics)
  - [Host Hardening & Continuity](#host-hardening--continuity)
  - [Operator Experience](#operator-experience)
  - [Secure Development Workflow](#secure-development-workflow)
- [4. Requirements](#4-requirements)
- [5. Quick Start (Interactive Press)](#5-quick-start-interactive-press)
- [6. Advanced and Unattended Builds](#6-advanced-and-unattended-builds)
- [7. Post-Install Experience](#7-post-install-experience)
- [8. Operations and Maintenance](#8-operations-and-maintenance)
- [Project Structure](#project-structure)
- [10. Troubleshooting](#10-troubleshooting)
- [11. Additional Resources](#11-additional-resources)
- [License](#license)

---

## 1. Overview

The Kali Neural Defense Press automates the creation of a battle-hardened Kali Linux environment that trains, deploys, and maintains a neural-network intrusion detection stack. It handles the full lifecycle: downloading official Kali images, injecting preseeds and hardening scripts, preparing legal datasets (including Georgia Tech GA Tech collections), training neural models, and delivering an operator dashboard that unifies analytics, response controls, and recovery tooling.

The overarching goal remains **creating a hardened Kali Linux press containing a self-learning IDS**. Every script in this repository contributes toward that objective by layering automation, monitoring, and secure defaults onto the base operating system and surrounding hosts.

---

## 2. Architecture at a Glance

1. **Press automation** fetches the official installer or live ISO, verifies signatures, injects preseeds/first-boot tooling, and logs every step.
2. **First boot services** harden the guest, randomize network identity, ensure connectivity, and launch IDS setup tasks alongside host/VM-specific protections.
3. **Neural IDS pipeline** sanitizes datasets, trains a baseline model, captures live traffic, retrains on schedule, snapshots state, and restores automatically after tampering.
4. **Analytics and dashboards** expose next-generation telemetry (MITRE mapping, dwell time, burst/beacon detection, probability distributions, and more) through a boot-launched control menu and desktop shortcut.
5. **Host hardening extensions** protect Windows and Linux hosts, enforce SSH access controls, and provide ongoing malware, anti-wipe, and baseline integrity monitoring.
6. **Secure development workflow** equips maintainers with signing keys and static-analysis tooling so future changes maintain the same security bar.

---

## 3. Feature Highlights

### Press Automation
- **Single entry point:** `full_automation_setup.sh` installs the secure dev toolchain, prepares IDS assets, and runs the ISO press. When required inputs (mode, output path, working directory, Kali credentials, guest credentials) are missing it prompts interactively; otherwise it runs unattended.
- **Robust dependency bootstrap:** Both automation helpers install curl, gnupg, libarchive-tools, genisoimage, syslinux-utils, dialog, Python/pip, pre-commit tooling (Black, Flake8, Bandit, isort, ShellCheck, Codespell, Gitleaks), git, network discovery utilities (nmap, netdiscover, arp-scan, nbtscan, dnsrecon, whatweb, enum4linux, nikto, sslscan, snmp utilities, masscan, traceroute), and verification tools before any downloads.
- **Connectivity & resource guards:** Presses abort (or throttle) when free RAM drops below 2 GB, when less than 8 GB remains in the working or output directories, or when networking cannot be established even after SD-WAN/Cisco/VMware interface activation.
- **Verified downloads:** `build_custom_iso.sh` retries and resumes ISO/checksum transfers, verifies SHA256 hashes and Kali’s GPG signatures, and only imports the signing key when it is missing.
- **Deterministic output:** Previous ISOs/checksums are purged before each run, the finished image must exist (non-empty) or the script aborts, and final hashes are saved, printed, and optionally signed. Timestamped logs capture every command.
- **Environment baselines:** `press_environment_report.sh` now snapshots OS, hardware, storage, networking, virtualization/container context, security posture (AppArmor/SELinux/sysctls), listening sockets, tooling availability, pending package/security updates, reboot requirements, and top CPU/memory consumers into Markdown reports with a warning summary so operators can see gaps before each press run.
- **Reusable configuration:** Environment variables, `press.conf`, `PRESS_CONF`, `-c`, `-k`, `-S`, and `-a` flags support unattended presses, workspace retention, and configuration persistence. Interactive sessions can write answers back to configuration for future runs.

### Neural IDS & Analytics
- **Dataset sanitization:** `packet_sanitizer.py` filters malicious noise; sanitization runs before training and during retraining cycles to mitigate poisoning/desensitization attacks.
- **Baseline OS modeling:** `nn_os_train.py` fingerprints host characteristics and trains a lightweight NN to detect configuration drift.
- **Core IDS service:** `nn_ids_service.py` scores packets using a configurable threshold, logs alerts with confidence values, rotates logs, and maintains rich analytics (probability spread, TTL/length/flag distributions, streak counters, port/protocol trends, MITRE kill-chain stage totals, tactic transitions, dwell time, burst/beacon detection, risk-ranked source profiles, zero-day counters, APT watchlists, multi-tactic diversity, IPv4/IPv6 splits, subnet hotspots, hourly/minute timelines, rolling history, and more) while layering behavioural roles (scanner, brute-forcer, beaconing, lateral-mover, exfiltrator, high-risk, protocol-hopper, zero-day), fan-out and port-diversity leaders, and campaign-scoring intelligence. Adaptive EWMA baselines now flag sudden traffic surges, probability spikes, and intensity scores so high-velocity campaigns surface immediately in dashboards and alert messages.
- **Continuous learning:** `nn_ids_capture.py` gathers live traffic, `nn_ids_retrain.py` merges datasets with captured samples, and `nn_ids_adversarial.py` generates annotated adversarial packets for resilient training.
- **Self-healing:** Timed snapshot/restore services persist IDS weights/datasets, while `nn_ids_resource_monitor.py` and `nn_ids_healthcheck.py` restart the IDS if resource limits are exceeded or binaries disappear.
- **Advanced detectors:**
  - **GA Tech process analysis (`nn_process_gt.py`):** Builds/updates a neural classifier, merges heuristic risk scoring with probability thresholds, refreshes benign baselines, logs ROC AUC/confusion metrics, streams detections with CLI monitor options, and stores context-rich CSV entries.
  - **GA Tech syscall analysis (`nn_syscall_gt.py`, `nn_syscall_monitor.py`):** Trains and monitors for malicious syscall windows, logging metrics and detections with tunable thresholds.
- **Automated defenses:** `nn_ids_autoblock.py` drops repeat offenders and expires rules after 24 hours; `threat_feed_blocklist.py` ingests community blocklists; `/etc/nn_ids.conf` toggles sanitization, notifications, discovery behaviour, autoblocking, threat-feed enforcement, and alert thresholds.

### Host Hardening & Continuity
- **First boot routines:** `firstboot.sh` (and the simplified `firstboot_single.sh`) apply Linux hardening, randomize MAC addresses, configure network I/O logging (ports 5775 inbound / 7557 outbound), enforce SSH access controls, schedule ClamAV/Lynis/rkhunter scans, initialize AppArmor/AIDE, seed psad, capture baseline audits, enable IDS timers, perform network discovery, and launch the operator dashboard.
- **Cross-host protections:**
  - **Windows:** `host_hardening_windows.sh` transfers/executes `windows_hardening.ps1`, enabling firewall logging, Sysmon, Defender ASR/PUA, TLS 1.2, Controlled Folder Access, SMBv1 disablement, exploit mitigations, script-block logging, and daily updates.
  - **Linux:** `host_hardening_linux.sh` enforces firewalls, disables root login/password auth, enables unattended upgrades, runs baseline scans, enforces AppArmor/AIDE/sysctl, and can rebuild benign process baselines.
  - **VM contextual hardening:** `vm_windows_env_hardening.sh`, `vm_linux_env_hardening.sh`, and `vm_pro_hardening.sh` adjust policies for host-aware settings, including clipboard restrictions, firewall tightening, kernel hardening, remounts, and needrestart installation.
- **Resilience:** `anti_wipe_monitor.sh` guards critical directories with inotify, reapplying immutable flags when tampering is detected; `internet_access_monitor.sh` maintains outbound access and restarts networking when necessary; `ssh_access_control.sh` enforces whitelist/blacklist policies.

### Operator Experience
- **Dashboard everywhere:** `ids_menu.sh` is a dialog-based control center launched by cron at login and via `ids_menu.desktop`. Operators can:
  - Toggle notifications, packet sanitization, autoblocking, threat feed enforcement, and network discovery response (auto/manual/notify/none).
  - Inspect alert analytics (including next-gen insights, behavioural role tagging, fan-out/campaign watchlists, EWMA surge ratios, probability spike leaders, and intensity scoring), recent history, top offenders, and probability distributions.
  - Launch/monitor GA Tech process & syscall scans, view their training logs, refresh baselines, and summarize detections.
  - Run rkhunter, Lynis, ClamAV, or combined scans; view summaries via `scan_log_summary.py`.
  - Manage blocked IP addresses (list/unblock), snapshot/restore IDS models, restart IDS services, generate adversarial samples, trigger dataset sanitization, refresh threat feeds, run the network discovery suite, and open reports/logs (threat feed, network I/O, port alerts, autoblock actions, process monitor, resource monitor, anti-wipe, network discovery HTML, hourly IDS reports, etc.).
- **Discovery reports:** `network_discovery.sh` plus `network_discovery_visualize.py` produce comprehensive host/service mapping with HTML visualization stored at `~/Desktop/initial network discovery`.
- **Logging clarity:** Structured logs land in `/var/log/nn_ids_alerts.log`, `/var/lib/nn_ids/alert_stats.json`, `/opt/nnids/*.csv`, `/var/log/ga_tech_*.log`, `/var/log/inbound*.log`, `/var/log/outbound*.log`, and baseline directories. Logrotate entries prevent disk exhaustion.

### Secure Development Workflow
- **Secure dev bootstrap:** `secure_dev_env.sh` installs VS Code (when desired), static analysis tooling, git hooks, and generates a local GPG key for signed commits.
- **AI-assisted iteration:** `ai_agent_commands.sh` showcases how to query AI helpers for refactoring ideas.
- **Quality gates:** `.pre-commit-config.yaml` pairs with the installed tooling; `verify_readme_modules.sh` keeps documentation aligned with repository files.

---

## 4. Requirements

| Resource | Minimum | Notes |
| --- | --- | --- |
| Host OS | Debian/Ubuntu/Kali with root access | Scripts expect apt-based systems and root privileges. |
| Disk space | ≥ 8 GB free in working/output directories | Checked before downloads and builds. |
| Memory | ≥ 2 GB available | Workloads throttle when under 2 GB and will warn/abort when extreme. |
| Network | Reliable internet with access to kali.org mirrors and GA Tech dataset mirrors | Connectivity is verified before downloads; SD-WAN/Cisco/VMware interfaces are activated if primary links fail. |
| GPG key (optional) | Existing secret key for signing checksums | If absent, checksum signing is skipped; secure dev bootstrap can generate one. |

---

## 5. Quick Start (Interactive Press)

1. **Clone this repository** onto a privileged host.
2. **Run the automation helper:**
   ```bash
   sudo ./full_automation_setup.sh
   ```
3. **Respond to prompts** for build mode (installer vs live), output ISO path (defaults to current directory), working directory, Kali username/password, and guest account credentials. Missing values are requested interactively.
4. The helper installs prerequisites, verifies connectivity, prepares the secure development environment, executes IDS setup tasks, downloads the chosen Kali ISO from the official installer or live feed, validates SHA256 and GPG signatures, injects preseeds/first-boot/IDS modules, and emits the finished ISO plus `.sha256` hash and build log.
5. **Review the output** — the ISO lands beside the script, a matching `.sha256` file stores the checksum, an environment snapshot `press_environment_*.md` captures host details (including patch posture, reboot requirements, and resource hotspots), and a timestamped log documents the run. Use the hash (and optional signature) to verify integrity before deployment.

---

## 6. Advanced and Unattended Builds

- **Configuration files:** Populate `press.conf` or supply an alternate path via `-c`/`PRESS_CONF`. Use `-S` to save current answers without running a build.
- **Environment variables:** `PRESS_MODE`, `PRESS_ISO`, `PRESS_WORKDIR`, `PRESS_KALI_USER`, `PRESS_KALI_PASS`, `PRESS_GUEST_USER`, and `PRESS_GUEST_PASS` override prompts. Combine with `-a` for fully unattended presses.
- **Workspace retention:** Pass `-k` to keep the temporary working directory for inspection; otherwise it is purged on success.
- **Direct ISO builder usage:**
  ```bash
  sudo ./build_custom_iso.sh --mode installer \
       --iso ./kali-custom.iso \
       --workdir /tmp/kali-build \
       --kali-user defender --kali-pass 'StrongPass!' \
       --guest-user analyst --guest-pass 'AnotherStrongPass!'
  ```
  The builder handles dependency installation, downloads, verification, injection, ISO repacking, checksum/signature output, log generation, cached ISO reuse (when hashes match), and validation that required scripts (preseed, first boot, dashboards, services) exist inside the image. A dedicated `download_iso` helper provides progress bars and waits for completion before customization begins.
- **Simulation mode:** `full_automation_setup.sh -n` and `build_custom_iso.sh -n` print every command (with line numbers) without executing, enabling dry runs for audits and training.

---

## 7. Post-Install Experience

After installing the pressed ISO:

- **First boot automation** performs (among many others):
  - MAC address randomization and network I/O logging enforcement (ports 5775 inbound, 7557 outbound) with log rotation.
  - Connectivity checks plus SD-WAN/Cisco/VMware fallbacks and firewall adjustments to maintain outbound access.
  - SSH whitelist/blacklist enforcement, dpkg self-healing if needed, package integrity verification via `debsums`, quick Lynis run, psad activation, and baseline snapshot creation.
  - Deployment of anti-wipe guards, resource monitors, threat feed updaters, IDS capture/retrain/health timers, snapshot/restore automation, dataset sanitization timers, ClamAV daemon updates, and scheduled malware/system scans.
  - Execution of GA Tech dataset downloads, OS baseline training, neural IDS training (in parallel with capture), and log configuration.
  - Launch of the comprehensive network discovery workflow with HTML visualization saved under `~/Desktop/initial network discovery`.
  - Creation of Kali and guest accounts with requested credentials and Docker group membership for the Kali user.
  - Installation of the IDS Control Menu desktop shortcut and addition of a cron job to auto-launch the dashboard each login.

- **IDS configuration:** Tweak `/etc/nn_ids.conf` to adjust packet sanitization, notification policy, discovery mode (auto/manual/notify/none), autoblocking, threat-feed enforcement, and probability thresholds for IDS, GA Tech process, and GA Tech syscall detectors.

- **Operator dashboard:** Run `ids_menu.sh` (or click the desktop icon) to manage IDS state, launch scans, view analytics (including MITRE kill-chain, tactic transitions, dwell time, risk scores, burst/beacon detection, etc.), manage blocked IPs, interact with GA Tech models, run network discovery, and access logs/reports.

- **Reports & logs:**
  - IDS alerts: `/var/log/nn_ids_alerts.log`
  - IDS analytics cache: `/var/lib/nn_ids/alert_stats.json`
  - GA Tech process alerts/training: `/var/log/ga_tech_proc_alerts.log`, `/var/log/ga_tech_proc_train.log`, `/opt/nnids/ga_proc_detections.csv`
  - GA Tech syscall alerts/training: `/var/log/ga_tech_sys_alerts.log`, `/var/log/ga_tech_sys_train.log`, `/opt/nnids/ga_sys_detections.csv`
  - Process/service monitor: `/opt/nnids/process_log.csv`
  - Network logs: `/var/log/inbound*.log`, `/var/log/outbound*.log`
  - Threat feed, autoblock, resource monitor, anti-wipe, discovery, and scan summaries are accessible from the dashboard and stored in `/var/log/` or `~/Desktop/initial network discovery` as appropriate.

---

## 8. Operations and Maintenance

- **Threat intelligence:** Use the dashboard to force a threat-feed refresh or view update logs. The timer keeps feeds current automatically.
- **Model management:** Snapshot or restore IDS state, retrain on demand, or generate adversarial samples from `ids_menu.sh`. Snapshots and datasets live in `/opt/nnids/snapshots` (managed by the snapshot/restore services).
- **Process & syscall monitoring:** Launch continuous or timed monitors from the dashboard or run `nn_process_gt.py` / `nn_syscall_monitor.py` directly with CLI options (`--monitor`, `--interval`, `--duration`, `--risk-threshold`, etc.).
- **Sanitization and recovery:** `nn_ids_sanitize.py` cleans datasets on a schedule; `nn_ids_restore.py` rebuilds IDS weights from the most recent snapshot whenever tampering is detected.
- **Connectivity assurance:** `internet_access_monitor.timer` checks connectivity periodically; logs surface in `/var/log/` for auditing. Adjust whitelist/blacklist rules via `/opt/nnids/ssh_whitelist.conf` and `/opt/nnids/ssh_blacklist.conf` if remote access policies change.
- **Security scans:** Daily Cron jobs run Lynis, rkhunter, and ClamAV. Use `scan_log_summary.py` or the dashboard to consolidate results.
- **Documentation validation:** Run `./verify_readme_modules.sh` after modifying modules or this README to ensure the Project Structure section remains accurate.
- **Secure development:** Execute `./secure_dev_env.sh` on contributor machines to install linting, scanning, and GPG signing prerequisites before committing. Pre-commit hooks keep coding standards consistent.

---

## Project Structure

Scripts and services work together as modular building blocks. Every module listed below is included in the pressed ISO.

- `ai_agent_commands.sh` – Example helper showing how to interact with AI-driven refactoring workflows.
- `anti_wipe_monitor.sh` / `anti_wipe_monitor.service` – Watch critical directories and restore immutable flags when wipe activity is detected.
- `build_custom_iso.sh` – Progress-aware ISO builder with dependency bootstrap, mirror fallback, validation, logging, and configuration support.
- `firstboot.sh` – Comprehensive first-boot hardening and orchestration script for full builds.
- `firstboot_single.sh` – Streamlined first-boot routine for single-OS installs without Windows integrations.
- `full_automation_setup.sh` – One-command orchestrator installing prerequisites, preparing IDS components, and invoking the ISO builder.
- `host_hardening_linux.sh` – Apply Linux host security (firewall, SSH lockdown, unattended upgrades, baseline scans, AppArmor/AIDE, sysctl hardening).
- `host_hardening_windows.sh` – Transfer and run Windows hardening automation over SSH.
- `ids_menu.desktop` – Desktop launcher for the IDS Control Menu.
- `ids_menu.sh` – Dialog-based operator dashboard covering IDS controls, analytics, scans, GA Tech tooling, snapshots, and log viewers.
- `internet_access_monitor.sh` / `internet_access_monitor.service` / `internet_access_monitor.timer` – Maintain outbound connectivity, reopen firewall paths, and restart networking when necessary.
- `kali-preseed.cfg` – Automated installer preseed incorporating hardening packages, placeholders, and service enablement for full builds.
- `kali-preseed-single.cfg` – Preseed variant for single-OS installs without Windows host hardening assets.
- `mac_randomizer.sh` / `mac_randomizer.service` – Randomize network interface MAC addresses on every boot.
- `network_discovery.sh` – Run extensive host/service discovery with optional vulnerability scans and per-host diagnostics.
- `network_discovery_visualize.py` – Parse discovery outputs and generate HTML visualizations.
- `network_io_monitor.sh` / `network_io_monitor.service` – Enforce dedicated inbound/outbound ports (5775/7557) and log traffic with rotation.
- `nn_ids.conf` – Central configuration toggling sanitization, notifications, discovery mode, autoblocking, threat feed usage, and detection thresholds.
- `nn_ids.service` – Systemd unit powering the neural IDS daemon.
- `nn_ids_adversarial.py` – Generate annotated adversarial packets for hardening the IDS model.
- `nn_ids_autoblock.py` / `nn_ids_autoblock.service` / `nn_ids_autoblock.timer` – Automatically block repeated offenders and expire firewall entries after 24 hours.
- `nn_ids_capture.py` / `nn_ids_capture.service` / `nn_ids_capture.timer` – Capture live packet features for subsequent retraining.
- `nn_ids_healthcheck.py` / `nn_ids_healthcheck.service` / `nn_ids_healthcheck.timer` – Verify IDS health, restart services on failure, and rotate logs.
- `nn_ids_report.py` / `nn_ids_report.service` / `nn_ids_report.timer` – Produce hourly IDS summaries highlighting top offending IPs.
- `nn_ids_resource_monitor.py` / `nn_ids_resource_monitor.service` / `nn_ids_resource_monitor.timer` – Watch CPU/RAM usage and recycle the IDS when limits are exceeded.
- `nn_ids_restore.py` / `nn_ids_restore.service` / `nn_ids_restore.timer` – Restore or rebuild IDS models from snapshots after tampering events.
- `nn_ids_retrain.py` / `nn_ids_retrain.service` / `nn_ids_retrain.timer` – Periodically retrain the IDS on sanitized baseline plus captured traffic.
- `nn_ids_sanitize.py` / `nn_ids_sanitize.service` / `nn_ids_sanitize.timer` – Perform scheduled dataset sanitization to fight poisoning attacks.
- `nn_ids_service.py` – Core neural IDS daemon with advanced analytics, alerting, and statistics tracking.
- `nn_ids_setup.py` – Prepare datasets, sanitize samples, and kick off model training during provisioning.
- `nn_ids_snapshot.py` / `nn_ids_snapshot.service` / `nn_ids_snapshot.timer` – Snapshot IDS weights and datasets on a schedule for resilience.
- `nn_os_train.py` – Train a baseline neural model that detects OS drift for additional anomaly detection.
- `nn_process_gt.py` – Download/train GA Tech process classifier, log metrics, merge heuristic scores, and monitor processes.
- `nn_syscall_gt.py` – Train GA Tech syscall classifier and log detailed metrics for evaluation.
- `nn_syscall_monitor.py` / `nn_syscall_monitor.service` – Continuously score syscall windows and log suspicious behaviour.
- `packet_sanitizer.py` – Helper shared across training phases for cleansing datasets.
- `port_socket_monitor.py` / `port_socket_monitor.service` / `port_socket_monitor.timer` – Detect unexpected listening ports and log alerts.
- `press_environment_report.sh` – Capture host, storage, network, virtualization/container context, security-module status, listening sockets, tooling details, pending upgrades/reboot requirements, and top resource consumers in a Markdown report (with warnings) before the press runs.
- `process_monitor.service` / `process_monitor.timer` – Systemd wrappers powering the process/service monitoring routine.
- `process_service_monitor.py` – Establish baselines, detect unexpected processes/services, and tag findings for later review.
- `scan_log_summary.py` – Summarize rkhunter, Lynis, and ClamAV outputs for operator review.
- `secure_dev_env.sh` – Install secure coding tooling, configure git defaults, and generate a GPG key for signed commits.
- `security_scan_scheduler.sh` – Configure recurring Lynis, rkhunter, and ClamAV scans via cron.
- `setup_nn_ids.sh` / `setup_nn_ids.service` – Install prerequisites and launch the asynchronous IDS setup workflow.
- `ssh_access_control.sh` – Enforce SSH whitelist/blacklist policies using iptables chains.
- `ssh_blacklist.conf` – Default SSH blacklist configuration file.
- `ssh_whitelist.conf` – Default SSH whitelist configuration file.
- `threat_feed_blocklist.py` / `threat_feed_blocklist.service` / `threat_feed_blocklist.timer` – Ingest blocklists and update firewall rules automatically.
- `verify_readme_modules.sh` – Ensure README module documentation stays in sync with repository contents.
- `vm_linux_env_hardening.sh` – Apply Linux-host-aware VM safeguards.
- `vm_pro_hardening.sh` – Apply professional-grade hardening within the VM (kernel tuning, AppArmor enforcement, secure remounts).
- `vm_windows_env_hardening.sh` – Harden the VM when running on a Windows host (firewall adjustments, clipboard restrictions, etc.).
- `windows_hardening.ps1` – Comprehensive Windows 11 hardening script executed remotely from the Kali VM.

---

## 10. Troubleshooting

| Symptom | Resolution |
| --- | --- |
| ISO download stalls or returns `403 Forbidden` | Mirror fallback triggers automatically; ensure outbound port 7557 is permitted. Rerun with `-n` to confirm configuration, then retry when connectivity is restored. |
| Build stops at GPG key import (`Process: 1, unchanged: 1`) | The builder now skips re-importing existing keys. If encountered, delete `~/.gnupg/pubring.kbx` only if corrupt, then rerun. |
| Press fails due to missing `dpkg-split` | The automation scripts reinstall `dpkg` automatically. If running manually, execute `sudo ./build_custom_iso.sh` so the safeguard applies. |
| `verify_readme_modules.sh` reports missing/undocumented modules | Update the Project Structure section (above) and rerun the script until it reports success. |
| IDS alerts overwhelm due to low confidence threshold | Increase `NN_IDS_THRESHOLD` (and GA Tech thresholds) in `/etc/nn_ids.conf`, then restart services via the dashboard. |
| Network discovery tools unavailable | Ensure the build scripts ran to completion; they install the toolchain. If performing manual installs, run `sudo ./secure_dev_env.sh` and `sudo ./full_automation_setup.sh` first. |
| Cron-launched dashboard not appearing | Confirm the user’s crontab contains the startup entry and `dialog` is installed. Launch manually with `~/ids_menu.sh` or rerun `firstboot.sh`. |

---

## 11. Additional Resources

- Run `./verify_readme_modules.sh` to validate documentation alignment.
- Consult `DEV_NOTES.md` for contributor guidance and `GOALS.md` for roadmap objectives.
- `extended_readme.md` contains historical context and extended explanations of earlier iterations.

---

## License

This project is released under the terms of the [MIT License](LICENSE). Review and comply with applicable laws before downloading third-party datasets or executing automated hardening steps.

