# Automated Secure Kali Linux VM with Windows 11 Host Hardening

> Whitehatting within a compromised Windows 11 environment — project by Alexander Raymond Graham (Minc- Anonymous)

## Table of Contents

- [Project Overview](#project-overview)
- [Project Goals](#project-goals)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation and Setup](#installation-and-setup)
  - [1. Creating the Preseed Configuration File](#1-creating-the-preseed-configuration-file)
  - [2. Building the Custom Kali Linux ISO](#2-building-the-custom-kali-linux-iso)
  - [3. Configuring Windows 11 for Remote Management](#3-configuring-windows-11-for-remote-management)
  - [4. Automating Host (Windows 11) Hardening from Kali VM](#4-automating-host-windows-11-hardening-from-kali-vm)
- [Usage](#usage)
  - [Running the Custom Kali ISO](#running-the-custom-kali-iso)
  - [Executing the Host Hardening Script](#executing-the-host-hardening-script)
- [Security Considerations](#security-considerations)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [Additional Resources](#additional-resources)
- [License](#license)
- [Developer Notes](#developer-notes)

---

## Project Overview

This project provides a comprehensive solution for deploying an **extremely secure Kali Linux Virtual Machine (VM)** and automating the **hardening of a Windows 11 host** from within the VM. By utilizing a customized preseed configuration file and automated scripts, the setup ensures that both the Kali VM and the Windows host adhere to stringent security standards from the moment of deployment.

---

## Project Goals

The overarching goal is **creating a hardened Kali Linux press containing a self-learning IDS**. This repository evolves toward that aim through modular scripts and continuous automation.

Key objectives:

- Harden the Kali installation using a preseed file and first boot services.
- Train and deploy a neural-network-based IDS using legal datasets.
- Provide host hardening tools for Windows environments.
- Maintain clear documentation and developer notes to encourage collaboration.

---

## Features

- **Automated Kali Linux Installation**: Uses a preseed file to automate the installation process with extensive hardening measures.
- **Custom Security Configurations**: Implements best practices and advanced security settings based on CIS Benchmarks and academic research.
- **First Boot Hardening**: Executes additional hardening commands during the first startup using systemd services.
- **Automated Windows 11 Host Hardening**: Utilizes PowerShell scripts to remotely harden a Windows 11 host from the Kali VM. Controlled Folder Access is enabled and SMBv1 is disabled to reduce ransomware and network attack vectors.
- **Automated Windows Remote Setup**: The Windows hardening script installs and enables OpenSSH and PowerShell Remoting, enables transcript logging, and schedules daily updates.
- **Enhanced Windows Hardening**: Firewall logging is enabled, Sysmon is installed for system telemetry, Attack Surface Reduction rules are turned on, TLS 1.2 is enforced, and the Security event log size is increased.
- **Additional Windows Protections**: LLMNR is disabled, PowerShell script block logging is enabled, and system-wide exploit mitigations are applied.
- **Windows Host-Aware VM Hardening**: Additional firewall and virtualization tweaks protect the Kali VM when running on a Windows host.
- **Automated Linux Host Hardening**: Bash script connects over SSH to apply firewall rules and security tools on a Linux host. Root login and password authentication are disabled, unattended upgrades are enabled, and baseline rkhunter and Lynis scans run automatically.
- **Extended Linux Protections**: AppArmor is enforced, AIDE initializes a file-integrity database, and hardened sysctl parameters disable redirects and enforce address space randomization.
- **Linux Host-Aware VM Hardening**: Extra restrictions are applied when the VM is hosted on a Linux machine.
- **AI Agent Integration**: Optional script demonstrates how to request code improvement suggestions from a generative AI service.
- **Comprehensive Documentation**: Detailed instructions to guide users through setup, customization, and maintenance.
   - **Full Automation Helper**: `full_automation_setup.sh` installs the secure dev environment, prepares IDS components, and builds the custom ISO. It prompts only for missing build mode, output path, working directory, or credentials; if all are supplied via flags, environment variables, or a `press.conf` file, it runs unattended. Defaults select installer mode, drop the ISO in the current directory, and use `/tmp/kali-auto-build` for workspace. `-a` forces unattended mode and errors if required values are missing, `-c` chooses a different config file, `PRESS_CONF` can point to a config file as well, and `-k` keeps the working directory. `-S` saves provided options to the config file without prompting. After an interactive run it can still offer to save the answers to `press.conf` for future automated presses. Every run writes a timestamped log file to the current directory, reports the ISO's SHA256 checksum for auditing, and saves that hash to a `.sha256` file alongside the image. When a GPG key is present, the checksum file is also signed for later verification. Before any downloads, it installs missing tools (curl, gnupg, libarchive-tools, genisoimage, syslinux-utils, dialog, nmap, netdiscover, arp-scan, nbtscan, dnsrecon, whatweb, enum4linux, nikto, sslscan, snmp, masscan, traceroute, git, pre-commit, shellcheck, flake8, bandit, black, codespell, gitleaks, python3-isort, python3, python3-pip) and confirms internet connectivity to prevent partial presses. If the underlying system has lost the `dpkg-split` helper, the script reinstalls `dpkg` automatically so package installs succeed. Before building, any existing ISO or checksum files are removed so stale artifacts can't mask failures, and after the build step the helper verifies that the ISO exists and aborts if it is missing or empty, ensuring presses never silently fail.
- **Disk Space Verification**: Both helper scripts verify at least 8GB of free space in the working and output directories before building, aborting early when storage is insufficient.
- **Memory Availability Check**: Both helpers check for at least 2GB of free RAM and throttle their workload when less is available.
- **Resilient ISO Downloads**: The ISO builder automatically retries and resumes downloads of the base image and checksums, allowing unattended presses to recover from transient network failures.
- **Mirror Fallback**: If the primary mirror is unreachable or returns errors like 403, the ISO builder transparently switches to an alternate Kali mirror so presses continue.
- **Automatic Dependency Bootstrap**: The ISO builder installs curl and gnupg before checking connectivity, enabling presses to run on freshly provisioned systems.
 - **Secure Remote Management**: Configures secure communication channels between Kali VM and Windows host using SSH or PowerShell Remoting.
- **Port Scan Detection with psad**: Monitors iptables logs for potential network attacks.
- **Baseline Auditing**: First boot verifies package integrity with `debsums` and performs a quick Lynis scan.
- **Scheduled Security Scans**: Daily `lynis`, `rkhunter`, and `clamscan` checks are configured via cron.
- **Wiper and Malware Protection**: ClamAV runs daily scans, critical system files are backed up and locked with immutable attributes, and an inotify-based monitor watches for deletion attempts to thwart destructive wipers.
- **MAC Address Randomization**: The primary network interface receives a new MAC on each boot.
- **Port-Separated Network I/O Logging**: All inbound traffic is forced through port 5775 and outbound traffic through port 7557, with each direction logged from the first boot for review.
- **SSH Access Control**: Whitelist or blacklist IPs for SSH; a startup script applies iptables rules based on configurable lists.
- **Internet Connectivity Guard**: A periodic check keeps outbound access open, enforces the dedicated 5775/7557 port split, and restores networking if connectivity is lost, activating SD-WAN, Cisco, or VMware interfaces to maintain at least one active link.
- **Initial Network Discovery**: After hardening completes, a one-time sweep leverages `nmap`, `masscan`, `netdiscover`, `arp-scan`, `nbtscan`, `dnsrecon`, and optional `whatweb`/`enum4linux` probes to profile local hosts, services, DNS/NetBIOS data, and web fingerprints. Each host is further checked with `nmap --script vuln`, `nikto`, `sslscan`, and `snmpwalk` where applicable. Logs and an HTML visualization are saved to `~/Desktop/initial network discovery`, including a verification that only ports 5775 and 7557 are reachable locally.
 - **IDS Control Menu**: A dialog-based dashboard toggles malicious packet notifications, packet sanitization, automatic IP blocking, and threat feed updates; chooses follow-up discovery mode; lists, blocks, or unblocks IPs; displays recent IDS alerts, training metrics, alert reports, threat feed updates, network I/O logs, port monitor alerts, autoblock actions, process monitor alerts, anti-wipe monitor logs, IDS resource logs, rkhunter scan logs, Lynis scan logs, ClamAV scan logs, and network discovery reports; can trigger a fresh network discovery; launch dataset sanitization or model retraining; refresh the threat feed; snapshot or restore IDS state; generate adversarial samples; restart the IDS service; run rkhunter, Lynis, or ClamAV scans individually or all at once; summarize scan logs; run and retrain the GA Tech process model, view its training log; and launches on boot via cron or the desktop shortcut.
- **Secure Coding Environment**: Optional script configures git with secure defaults and installs pre-commit tooling. Static analysis and secret-scanning tools (Black, Flake8, Bandit, ShellCheck, isort, Codespell, and Gitleaks) run via pre-commit hooks, and a GPG key is generated so commits are signed automatically.
- **Professional VM Hardening**: Extra kernel hardening, secure tmp mount, AppArmor enforcement, and needrestart ensure the VM meets professional standards.
- **Neural Network IDS**: Scripts fetch GA Tech malware datasets, train a neural network model, capture live traffic for additional learning, and periodically retrain the model. Training runs in parallel with packet capture and live analysis using systemd services.
- **Adversarial Packet Training**: Synthetic malicious packets augment the dataset and the IDS logs why flagged traffic is considered malicious (e.g., suspicious ports or flag combinations).
- **OS Baseline Modeling**: A small neural network records core OS characteristics to detect future configuration drift.
- **Training Metrics Logging**: Accuracy, F1, precision, recall, ROC AUC, and a confusion matrix are recorded after each training or retraining run.
- **IDS Hardening Defenses**: Dataset integrity checks, outlier removal, noise augmentation, and detection of repeated evasion attempts guard against poisoning and desensitization attacks.
- **Process and Service Monitoring**: A systemd timer runs a Python script that records a baseline of running processes and services, alerts when new or suspicious entries appear, and logs flagged processes to `/opt/nnids/process_log.csv` for later analysis.
- **GA Tech Process Model**: Optional helper downloads Georgia Tech's malicious process dataset, incorporates locally flagged hashes, trains a neural network while logging metrics, and scans running processes. The IDS dashboard can trigger scans, retrain the model, and review both alerts and training logs.
- **IDS Health Check and Log Rotation**: Additional timer ensures the IDS service is running and rotates IDS logs to prevent disk bloat.
- **IDS Resource Usage Monitoring**: Another timer verifies the IDS process stays within CPU and memory limits, restarting it if needed.
- **Training Log Rotation**: Model training metrics are logged and rotated to keep logs manageable.
- **Packet Sanitization**: Captured datasets are sanitized before training to remove malformed or out-of-range values. This can be toggled by editing `/etc/nn_ids.conf` and setting `NN_IDS_SANITIZE=0`.
- **Automated Dataset Sanitization**: A timer-driven script periodically cleans the IDS datasets to prevent poisoning.
- **Smart Port Monitoring**: A timer-driven script records listening ports and logs unexpected changes.
- **Automatic IP Blocking**: Repeated IDS alerts trigger a script that blocks offending IP addresses via iptables. This behavior is configurable via the IDS menu or config file.
- **Probability-Based Alerts**: IDS alerts include a confidence score, and the detection threshold can be tuned via `NN_IDS_THRESHOLD` in `/etc/nn_ids.conf`.
- **Auto-Unblocking**: Blocked IPs are automatically removed after 24 hours to avoid permanent bans.
- **IDS Alert Reporting**: A timer summarizes new IDS alerts each hour and logs counts of offending IPs.
- **Threat Feed IP Blocking**: Daily job fetches community blocklists and automatically drops traffic from known malicious IPs. This can be disabled through the IDS menu or configuration.
- **Self-Healing Snapshots**: Daily snapshots of the IDS model and datasets allow automatic restoration or retraining if files are wiped.
- **Module Consistency Check**: `verify_readme_modules.sh` confirms every script listed in the Project Structure exists and warns about scripts in the repository that are missing from the list.

---

## Project Structure

Scripts are organized as modules that work together to produce the hardened image:

- `kali-preseed.cfg` – Automates the base installation and seeds security packages.
- `kali-preseed-single.cfg` – Variant preseed for single-OS installs without Windows host hardening.
- `firstboot.sh` – Runs once after installation to apply further hardening and invoke other modules.
- `firstboot_single.sh` – Simplified first boot script used for standalone installs without Windows host integration.
- `host_hardening_windows.sh` and `windows_hardening.ps1` – Harden a Windows host from the VM.
- `host_hardening_linux.sh` – Harden a Linux host via SSH.
- `vm_windows_env_hardening.sh` – Applies additional VM protections when a Windows host is detected.
- `vm_linux_env_hardening.sh` – Applies additional VM protections when a Linux host is detected.
- `security_scan_scheduler.sh` – Sets up recurring Lynis and rkhunter scans.
- `process_service_monitor.py`, `process_monitor.service`, and `process_monitor.timer` – Monitors running processes and services via a systemd timer and records tagged events to `/opt/nnids/process_log.csv`.
- `nn_process_gt.py` – Downloads the Georgia Tech malicious process dataset, augments it with locally flagged hashes, trains a neural network (logging metrics to `/var/log/ga_tech_proc_train.log`), and logs flagged processes to `/var/log/ga_tech_proc_alerts.log`.
- `vm_pro_hardening.sh` – Applies professional-level kernel and AppArmor hardening within the VM.
- `port_socket_monitor.py`, `port_socket_monitor.service`, and `port_socket_monitor.timer` – Detects new listening ports and logs suspicious ones.
- `nn_ids_adversarial.py` – Generates synthetic malicious packet features for adversarial training.
- `network_discovery.sh` – Runs an expansive reconnaissance suite (`nmap`, `masscan`, `netdiscover`, `arp-scan`, `nbtscan`, `dnsrecon`, etc.) and saves results under `~/Desktop/initial network discovery` for baseline analysis, including per-host `nmap --script vuln`, `nikto`, `sslscan`, and `snmpwalk` checks.
- `network_discovery_visualize.py` – Parses discovery results and creates an HTML report with port-distribution graphs.
- `scan_log_summary.py` – Summarizes rkhunter, Lynis, and ClamAV logs.
- `ids_menu.sh` – Interactive menu to toggle IDS notifications, packet sanitization, automatic IP blocking, threat feed blocking, set network discovery response modes, manage blocked IP addresses, view IDS alerts, training metrics, alert reports, threat feed logs, network I/O logs, port monitor alerts, autoblock actions, and network discovery reports; launch network discovery; trigger dataset sanitization; retrain the model; refresh the threat feed; snapshot or restore IDS state; generate adversarial samples; restart the IDS service; run rkhunter, Lynis, or ClamAV scans individually or all at once; summarize scan logs. A cron job launches the menu at boot.
- `ids_menu.sh` – Interactive menu to toggle IDS notifications, packet sanitization, automatic IP blocking, threat feed blocking, set network discovery response modes, manage blocked IP addresses, view IDS alerts, training metrics, alert reports, threat feed logs, network I/O logs, port monitor alerts, autoblock actions, and network discovery reports; launch network discovery; trigger dataset sanitization; retrain the model; refresh the threat feed; snapshot or restore IDS state; generate adversarial samples; restart the IDS service; run rkhunter, Lynis, or ClamAV scans individually or all at once; run and retrain the GA Tech process model, view its training log; summarize scan logs. A cron job launches the menu at boot.
- `ids_menu.desktop` – Desktop shortcut to open the IDS Control Menu.
- `ssh_access_control.sh`, `ssh_whitelist.conf`, `ssh_blacklist.conf` – Apply iptables rules enforcing SSH whitelist/blacklist lists.
- `nn_ids_healthcheck.py`, `nn_ids_healthcheck.service`, and `nn_ids_healthcheck.timer` – Ensure the IDS is active and rotate logs.
- `setup_nn_ids.sh`, `setup_nn_ids.service`, `nn_ids_setup.py`, and `nn_os_train.py` – Download datasets, build an OS baseline model, and train the initial neural network IDS.
- `nn_ids_service.py` and `nn_ids.service` – Run the neural-network IDS daemon.
- `nn_ids_capture.py`, `nn_ids_capture.service`, and `nn_ids_capture.timer` – Capture live traffic for retraining.
- `nn_ids_retrain.py`, `nn_ids_retrain.service`, and `nn_ids_retrain.timer` – Periodically retrain the model.
- `nn_ids_autoblock.py`, `nn_ids_autoblock.service`, and `nn_ids_autoblock.timer` – Block IPs automatically when repeated alerts are seen.
- `nn_ids_report.py`, `nn_ids_report.service`, and `nn_ids_report.timer` – Summarize alerts and log top offending IPs.
- `threat_feed_blocklist.py`, `threat_feed_blocklist.service`, and `threat_feed_blocklist.timer` – Fetch threat feeds, block listed IP addresses, and log updates.
- `nn_ids_resource_monitor.py`, `nn_ids_resource_monitor.service`, and `nn_ids_resource_monitor.timer` – Restart the IDS if it uses too much CPU or memory.
- `nn_ids_sanitize.py`, `nn_ids_sanitize.service`, and `nn_ids_sanitize.timer` – Periodically clean datasets to defend against poisoning.
- `nn_ids_snapshot.py`, `nn_ids_snapshot.service`, and `nn_ids_snapshot.timer` – Take periodic snapshots of the model and datasets.
- `nn_ids_restore.py`, `nn_ids_restore.service`, and `nn_ids_restore.timer` – Restore or rebuild the model from the latest snapshot if wiped.
- `packet_sanitizer.py` – Utility for cleansing datasets before model training.
 - `/etc/nn_ids.conf` – Configuration file controlling IDS options like packet sanitization, notification, discovery response, automatic IP blocking, threat feed blocking, and the alert probability threshold.
- `mac_randomizer.sh` and `mac_randomizer.service` – Randomize the MAC address at boot.
- `network_io_monitor.sh` and `network_io_monitor.service` – Log all network I/O to dedicated files.
- `internet_access_monitor.sh`, `internet_access_monitor.service`, and `internet_access_monitor.timer` – Verify connectivity, activate SD-WAN/Cisco/VMware interfaces if needed, and restart networking if access drops.
- `secure_dev_env.sh` – Configures secure git defaults and installs pre-commit tooling (Black, Flake8, Bandit, ShellCheck, isort, Codespell, Gitleaks), and auto-generates a GPG key for signed commits.
- `ai_agent_commands.sh` – Example commands demonstrating how to interact with the AI agent utilities.
- `.pre-commit-config.yaml` – Global configuration enabling Black, Flake8, Bandit, ShellCheck, isort, Codespell, and Gitleaks.
- `verify_readme_modules.sh` – Ensures every script listed in this section exists.
- `build_custom_iso.sh` – Downloads the latest Kali installer or live ISO, verifies its SHA256 checksum and GPG signature, installs any missing build dependencies, and packages the hardening scripts into a custom image. It checks internet connectivity up front and retries and resumes downloads to withstand transient network issues, showing progress and waiting for the ISO transfer to finish before moving on. The script prompts for build mode, ISO path, working directory, and credentials if they are not supplied, accepts the same values via environment variables or a `press.conf` configuration file for unattended use, automatically creates the output directory to avoid `could not create file` errors, removes any existing ISO and checksum files before building so failures aren't masked, and after an interactive run can write the answers to `press.conf` for future automation. Each run logs to a timestamped file, reuses a cached ISO if the checksum matches, saves the final image's SHA256 hash to a `.sha256` file, verifies the hash with `sha256sum -c`, signs the checksum when a GPG key is available, and flags `-c` and `-k` allow choosing an alternate config file and keeping the temporary working directory. If the system is missing the `dpkg-split` helper, the builder reinstalls `dpkg` before attempting any package operations. It only imports Kali's archive signing key if it's absent, avoiding errors when the key is already present. The builder validates the downloaded ISO and confirms that the final image contains the expected preseed and custom scripts.
- `full_automation_setup.sh` – Runs `secure_dev_env.sh`, IDS setup, and the ISO builder for a turnkey build. It installs missing prerequisites like curl and gnupg, then prompts for any unspecified build mode, output path, working directory, or credentials, with sensible defaults if left blank. If every option is provided via flags, environment variables, or `press.conf`, the script runs without interaction. Use `-a` to force unattended execution and fail if required values are missing. `-S` saves the supplied options to the config file without prompting, enabling immediate future runs with `-a`. When a config file is supplied, it is also passed to `build_custom_iso.sh` so both helpers share the same settings. After building, the script prints the ISO's SHA256 checksum, saves it to a `.sha256` file, verifies it with `sha256sum -c`, and signs the checksum when a GPG key is available.
- `anti_wipe_monitor.sh` and `anti_wipe_monitor.service` – Monitor critical directories for deletion and re-apply immutable flags if tampering is detected.

These modules are referenced in the preseed late commands and copied onto the ISO so the system is secured immediately after installation.

---

## Prerequisites

### Hardware

- **Host Machine**: Windows 11 PC with virtualization support (e.g., Intel VT-x or AMD-V).
- **Resources**: Adequate CPU, RAM, and storage to support Kali Linux VM and host operations.

### Software

- **Kali Linux ISO**: The build script fetches the required installer or live image automatically, but you can also download it manually from [Kali Downloads](https://www.kali.org/get-kali/).
- **Linux Environment**: A Linux system (can be a separate machine or a live environment) to create the custom ISO.
- **Tools**:
  - `genisoimage` or `mkisofs`: For building ISO images.
  - `syslinux-utils`: For making the ISO hybrid (optional for USB booting).
  - **SSH**: For remote access between Kali VM and Windows host.
  - **PowerShell Core**: Installed on Kali VM for executing PowerShell commands.

### Accounts and Permissions

- **Administrative Access**: Root or sudo privileges on the Kali Linux environment used to build the ISO.
- **Windows Admin Account**: An administrative user on Windows 11 for executing remote hardening scripts.

---

## Installation and Setup

### 1. Creating the Preseed Configuration File

The preseed file automates the Kali Linux installation process with extensive security configurations.

#### Steps:

1. **Create the Preseed File**:

   ```bash
   nano kali-preseed.cfg
   ```

2. **Paste the Enhanced Preseed Configuration**:

   ```bash
   # kali-preseed.cfg

   ### Localization
   d-i debian-installer/locale string en_US.UTF-8
   d-i console-setup/ask_detect boolean false
   d-i console-setup/layoutcode string us

   ### Network Configuration
   d-i netcfg/choose_interface select auto
   d-i netcfg/get_hostname string kali-vm
   d-i netcfg/get_domain string local

   ### Mirror Settings
   d-i mirror/country string manual
   d-i mirror/http/hostname string http.kali.org
   d-i mirror/http/directory string /kali
   d-i mirror/http/proxy string

   ### Account Setup
   ## Root Account
   d-i passwd/root-login boolean true
  d-i passwd/root-password password KALI_PASSWORD_PLACEHOLDER
  d-i passwd/root-password-again password KALI_PASSWORD_PLACEHOLDER

   ## Non-root User
  d-i passwd/user-fullname string KALI_USERNAME_PLACEHOLDER
  d-i passwd/username string KALI_USERNAME_PLACEHOLDER
  d-i passwd/user-password password KALI_PASSWORD_PLACEHOLDER
  d-i passwd/user-password-again password KALI_PASSWORD_PLACEHOLDER
   d-i user-setup/allow-password-weak boolean false

   ### Clock and Timezone
   d-i clock-setup/utc boolean true
   d-i time/zone string UTC
   d-i clock-setup/ntp boolean true

   ### Partitioning
   d-i partman-auto/method string crypto
   d-i partman-crypto/passphrase password DISK_ENCRYPTION_PASSPHRASE
   d-i partman-crypto/passphrase-again password DISK_ENCRYPTION_PASSPHRASE
   d-i partman-auto-lvm/guided_size string max
   d-i partman-auto/choose_recipe select atomic
   d-i partman/confirm_write_new_label boolean true
   d-i partman/choose_partition select finish
   d-i partman/confirm boolean true
   d-i partman/confirm_nooverwrite boolean true

   ### Base System Installation
   d-i base-installer/kernel/override-image string linux-image-amd64

   ### Package Selection
   tasksel tasksel/first multiselect standard, kali-desktop
   d-i pkgsel/include string \
       openssh-server \
       fail2ban \
       ufw \
       auditd \
       clamav \
       clamav-daemon \
       apparmor \
       unattended-upgrades \
       ntp \
       htop \
       curl \
       wget \
       vim \
       git \
       lynis \
       rkhunter \
       chkrootkit \
       sysstat \
       aide \
       docker.io \
       openssl \
       gnupg \
       net-tools \
       nmap \
       tcpdump \
       wireshark \
       ethtool \
       traceroute \
       dnsutils \
       debsums \
       apparmor-utils \
       apparmor-profiles-extra \
       secure-delete \
       chrony \
       psad
   d-i pkgsel/upgrade select full-upgrade

   ### Boot Loader Installation
   d-i grub-installer/only_debian boolean true
   d-i grub-installer/with_other_os boolean false
   d-i grub-installer/password-crypted password GRUB_PASSWORD_HASH

   ### Preseed Commands for Post-Installation Hardening
   d-i preseed/late_command string \
       # Enable and configure UFW firewall \
       in-target systemctl enable ufw; \
       in-target ufw default deny incoming; \
       in-target ufw default allow outgoing; \
       in-target ufw allow 22/tcp; \
       in-target ufw allow 80/tcp; \
       in-target ufw allow 443/tcp; \
       in-target ufw allow 8080/tcp; \
       in-target ufw enable; \
       \
       # Harden SSH configuration \
       in-target sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config; \
       in-target sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config; \
       in-target sed -i 's/^#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config; \
       in-target systemctl restart ssh; \
       \
       # Enable and configure Fail2Ban \
       in-target systemctl enable fail2ban; \
       in-target systemctl start fail2ban; \
       in-target cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; \
       in-target sed -i 's/^bantime = .*/bantime = 3600/' /etc/fail2ban/jail.local; \
       in-target sed -i 's/^maxretry = .*/maxretry = 5/' /etc/fail2ban/jail.local; \
       in-target systemctl restart fail2ban; \
       \
       # Enable and configure Auditd \
       in-target systemctl enable auditd; \
       in-target systemctl start auditd; \
       in-target cp /etc/audit/audit.rules /etc/audit/audit.rules.bak; \
       cat <<EOF > /target/etc/audit/audit.rules
       -w /etc/passwd -p wa -k passwd_changes
       -w /etc/shadow -p wa -k shadow_changes
       -w /etc/hosts -p wa -k hosts_changes
       -w /var/log -p wa -k log_changes
       -w /bin -p x -k bin_executions
       -w /usr/bin -p x -k usr_bin_executions
       -w /sbin -p x -k sbin_executions
       -w /usr/sbin -p x -k usr_sbin_executions
       EOF
       in-target systemctl restart auditd; \
       \
       # Enable AppArmor \
       in-target systemctl enable apparmor; \
       in-target systemctl start apparmor; \
       \
       # Configure Unattended Upgrades \
       in-target apt-get install -y unattended-upgrades; \
       in-target dpkg-reconfigure --priority=low unattended-upgrades; \
       \
       # Kernel Hardening via sysctl \
       echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf; \
       echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf; \
       echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf; \
       echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf; \
       echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.conf; \
       echo "fs.suid_dumpable=0" >> /etc/sysctl.conf; \
       echo "kernel.exec-shield=1" >> /etc/sysctl.conf; \
       echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf; \
       echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf; \
       echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf; \
       echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf; \
       echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.conf; \
       echo "net.ipv4.conf.all.secure_redirects=1" >> /etc/sysctl.conf; \
       echo "net.ipv4.conf.default.secure_redirects=1" >> /etc/sysctl.conf; \
       sysctl -p; \
       \
       # Restrict Permissions \
       chmod 700 /root; \
       chmod 700 /home/KALI_USERNAME_PLACEHOLDER; \
       echo "Authorized access only. Activity may be monitored." > /target/etc/issue; \
       cp /target/etc/issue /target/etc/issue.net; \
       in-target systemctl mask ctrl-alt-del.target; \
       echo "blacklist usb-storage" > /target/etc/modprobe.d/blacklist-usb.conf; \
       \
       # Enforce Password Policies \
       chage --maxdays 90 KALI_USERNAME_PLACEHOLDER; \
       chage --maxdays 90 root; \
       \
       # Remove Unnecessary Services and Packages \
       apt-get remove --purge -y telnet ftp nfs-common rpcbind; \
       apt-get autoremove -y; \
       apt-get clean; \
       \
       # Bash Configuration Enhancements \
       echo "alias ll='ls -la'" >> /home/KALI_USERNAME_PLACEHOLDER/.bashrc; \
       chown KALI_USERNAME_PLACEHOLDER:KALI_USERNAME_PLACEHOLDER /home/KALI_USERNAME_PLACEHOLDER/.bashrc; \
       echo "export HISTCONTROL=ignoredups:erasedups" >> /home/KALI_USERNAME_PLACEHOLDER/.bashrc; \
       echo "export TMOUT=300" >> /etc/profile; \
       \
       # Sudo Logging \
       echo "Defaults log_output" >> /etc/sudoers.d/logging; \
       mkdir /var/log/sudo; \
       chmod 750 /var/log/sudo; \
       systemctl restart rsyslog; \
       \
       # Install and Configure Additional Security Tools \
       apt-get install -y lynis rkhunter chkrootkit aide docker.io; \
       rkhunter --update; \
       rkhunter --propupd; \
       aideinit; \
       in-target cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db; \
       \
       # Configure AIDE for Integrity Checking \
       echo "/bin" >> /etc/aide/aide.conf; \
       echo "/sbin" >> /etc/aide/aide.conf; \
       echo "/usr/bin" >> /etc/aide/aide.conf; \
       echo "/usr/sbin" >> /etc/aide/aide.conf; \
       echo "/etc" >> /etc/aide/aide.conf; \
       echo "/var/log" >> /etc/aide/aide.conf; \
       \
        # Copy first boot and host hardening scripts \
        in-target cp /cdrom/install/firstboot.sh /usr/local/bin/firstboot.sh; \
        in-target cp /cdrom/install/host_hardening_windows.sh /usr/local/bin/host_hardening_windows.sh; \
        in-target cp /cdrom/install/windows_hardening.ps1 /usr/local/bin/windows_hardening.ps1; \
        in-target cp /cdrom/install/firstboot.service /etc/systemd/system/firstboot.service; \
        in-target chmod +x /usr/local/bin/firstboot.sh /usr/local/bin/host_hardening_windows.sh; \
        in-target systemctl enable firstboot.service; \
        \
        # Remove Temporary Files \
        rm /target/preseed/kali-preseed.cfg; \
        \
        # Final Cleanup \
       apt-get clean
   ```

3. **Replace Placeholder Variables**:

   - `KALI_PASSWORD_PLACEHOLDER`: Replace with a strong, unique password used for both the root and default Kali user.
   - `KALI_USERNAME_PLACEHOLDER`: Replace with the desired username for the default Kali account.
   - `DISK_ENCRYPTION_PASSPHRASE`: Replace with a secure passphrase for disk encryption.
   - `GRUB_PASSWORD_HASH`: Hash of the GRUB password generated with `grub-mkpasswd-pbkdf2`.
   - `HOST_IP`: IP address of the Windows host targeted by the post-boot hardening script.
   - `OPENAI_API_KEY`: Token for the optional AI agent helper script.

4. **Secure the Preseed File**:

   ```bash
   chmod 600 kali-preseed.cfg
   ```

---

### 2. Building the Custom Kali Linux ISO

The `full_automation_setup.sh` helper can create the image automatically. Populate a `press.conf` file with your desired settings and run the script. An example configuration is provided as `press.conf.example`. If no config file exists, the helper will prompt for missing values and offer to write them to `press.conf` for next time.

```bash
cp press.conf.example press.conf
sudo ./full_automation_setup.sh -c press.conf
```

Use `-k` if you need to inspect the working directory after the build. The ISO is written to the current directory and the temporary working directory is removed by default. The manual steps below remain for reference.

#### Steps:

1. **Mount the Original Kali ISO**:

   ```bash
   mkdir /mnt/kali-iso
   sudo mount -o loop kali-linux-latest-amd64.iso /mnt/kali-iso
   ```

2. **Copy ISO Contents to a Working Directory**:

   ```bash
   mkdir ~/kali-custom-iso
   rsync -a /mnt/kali-iso/ ~/kali-custom-iso
   sudo umount /mnt/kali-iso
   ```

3. **Add the Preseed File**:

   ```bash
   mkdir -p ~/kali-custom-iso/preseed
   cp kali-preseed.cfg ~/kali-custom-iso/preseed/kali-preseed.cfg
   ```

4. **Modify the Boot Configuration to Use the Preseed File**:

   - **For ISOLINUX**:

     Edit `~/kali-custom-iso/isolinux/txt.cfg` and add a new menu entry for the automated install.

     ```bash
     nano ~/kali-custom-iso/isolinux/txt.cfg
     ```

     Add the following entry:

     ```plaintext
     label auto
         menu label ^Automated Install (Preseed)
         kernel /install.amd/vmlinuz
         append auto=true priority=critical preseed/file=/cdrom/preseed/kali-preseed.cfg initrd=/install.amd/initrd.gz ---
     ```

   - **For GRUB**:

     If using GRUB, edit `~/kali-custom-iso/boot/grub/grub.cfg` and add a similar entry.

5. **Rebuild the ISO**:

   ```bash
   cd ~/kali-custom-iso
   sudo mkisofs -D -r -V "Kali Custom" -cache-inodes -J -l \
   -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot \
   -boot-load-size 4 -boot-info-table -o ~/kali-custom-auto.iso .
   ```

6. **Make the ISO Hybrid (Optional for USB Booting)**:

   ```bash
   sudo apt-get install syslinux-utils
   isohybrid ~/kali-custom-auto.iso
   ```

7. **Verify the ISO**:

   Test the ISO in a virtual machine environment (e.g., VirtualBox, VMware) before deploying it in production. The `build_custom_iso.sh` helper automatically checks the downloaded image against Kali's published SHA256 sums and verifies the GPG signature for authenticity.
   Alternatively, run the provided `build_custom_iso.sh` script to automate these steps. It will install required tools if they are missing and prompts for any unspecified values when executed without arguments:

```bash
# Interactive prompts
./build_custom_iso.sh

# Or specify options explicitly
./build_custom_iso.sh live kali-custom-live.iso
./build_custom_iso.sh installer kali-custom-installer.iso

# Or supply options via environment variables for an unattended run
MODE=live OUT_ISO=/tmp/kali.iso WORKDIR=/tmp/kbuild \
KALI_USERNAME=kali KALI_PASSWORD=kali123 \
GUEST_USERNAME=guest GUEST_PASSWORD=guest123 \
    ./build_custom_iso.sh

# If a `press.conf` file exists, the script uses values from it automatically
cp press.conf.example press.conf
./build_custom_iso.sh

# Specify an alternate config file
./build_custom_iso.sh -c mysettings.conf
# Or set it via environment variable
PRESS_CONF=mysettings.conf ./build_custom_iso.sh

# Keep the working directory for inspection
./build_custom_iso.sh -k
```

For an end-to-end run that installs prerequisites and prepares the IDS before building the ISO, use:

```bash
# Interactive (prompts for any missing values)
# On first run, answer prompts and optionally save them to press.conf
./full_automation_setup.sh

# Provide all options to run unattended
./full_automation_setup.sh -m installer -o /tmp/kali.iso -u kali -p kali123 -g guest -s guest123

# Or force unattended mode and fail if something is missing
./full_automation_setup.sh -m installer -o /tmp/kali.iso -u kali -p kali123 -g guest -s guest123 -a

# The helper also honors environment variables for these values
MODE=installer OUT_ISO=/tmp/kali.iso WORKDIR=/tmp/kbuild \
KALI_USER=kali KALI_PASS=kali123 GUEST_USER=guest GUEST_PASS=guest123 \
    ./full_automation_setup.sh -a

# Use PRESS_CONF to point to a different config file
PRESS_CONF=mysettings.conf ./full_automation_setup.sh -a
```


---

### 3. Configuring Windows 11 for Remote Management

To automate the hardening of the Windows 11 host from the Kali VM, enable secure remote management on Windows.

#### Steps:

#### Enable PowerShell Remoting

1. **Open PowerShell as Administrator**:

   - Press `Win + X` and select **Windows PowerShell (Admin)**.

2. **Enable PowerShell Remoting**:

   ```powershell
   Enable-PSRemoting -Force
   ```

3. **Configure Trusted Hosts (If Necessary)**:

   If the Kali VM is on a different network or requires specifying trusted hosts, run:

   ```powershell
   Set-Item wsman:\localhost\Client\TrustedHosts -Value "Kali_VM_IP"
   ```

   Replace `Kali_VM_IP` with the actual IP address of your Kali VM.

4. **Configure Firewall Rules**:

   Ensure that the firewall allows PowerShell Remoting:

   ```powershell
   Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
   ```

#### Set Up Authentication

1. **Use HTTPS for Encryption (Recommended)**:

   - **Generate a Self-Signed Certificate**:

     ```powershell
     New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName "your.domain.com"
     ```

     Replace `your.domain.com` with your actual domain name.

   - **Configure WinRM to Use HTTPS**:

     ```powershell
     $thumbprint = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=your.domain.com" }).Thumbprint
     winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{
         Hostname="your.domain.com";
         CertificateThumbprint="$thumbprint"
     }
     ```

     Replace `your.domain.com` with your domain and ensure the thumbprint matches the generated certificate.

2. **Set Up SSH-Based Authentication (Alternative)**:

   - **Install OpenSSH Server**:

     ```powershell
     Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
     ```

   - **Start and Enable the SSH Service**:

     ```powershell
     Start-Service sshd
     Set-Service -Name sshd -StartupType 'Automatic'
     ```

   - **Configure SSH for Key-Based Authentication**:

     - **Generate an SSH Key Pair on Kali**:

       ```bash
       ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_kali_windows
       ```

     - **Copy the Public Key to Windows**:

       ```bash
       scp ~/.ssh/id_rsa_kali_windows.pub user@windows_host_ip:"C:\Users\user\.ssh\authorized_keys"
       ```

       Replace `user` with your Windows username and `windows_host_ip` with the Windows host's IP address.

   - **Test SSH Access**:

     ```bash
     ssh -i ~/.ssh/id_rsa_kali_windows user@windows_host_ip
     ```

#### Create a Dedicated Administrative User

On Windows 11, create a user account specifically for remote management with strong credentials.

---

### 4. Automating Host (Windows 11) Hardening from Kali VM

With remote management configured, use scripts to automate the hardening of the Windows 11 host from the Kali VM.

#### Steps:

#### Develop the PowerShell Hardening Script

1. **Review `windows_hardening.ps1`**:

   The repository now includes a PowerShell hardening script (`windows_hardening.ps1`).
   Review the contents and adjust the commands as needed for your environment.

   ```powershell
   # windows_hardening.ps1

   # Installs OpenSSH and enables PowerShell Remoting
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Start-Service sshd; Set-Service sshd -StartupType Automatic
   Enable-PSRemoting -Force

   # Applies firewall and Defender settings, enforces password policies, enables BitLocker, activates PowerShell transcription logging, and schedules daily updates using PSWindowsUpdate.
```
   **Note**: Some commands, like enabling BitLocker, require TPM and may need user interaction or specific configurations. Ensure your Windows 11 host meets the prerequisites before enabling such features.

2. **Transfer the Script to Kali VM**:

   ```bash
   scp windows_hardening.ps1 KALI_USERNAME_PLACEHOLDER@kali-vm:/home/KALI_USERNAME_PLACEHOLDER/
   ```

1. **Review `host_hardening_windows.sh`**:

   This helper waits until the Windows host is reachable via SSH, copies `windows_hardening.ps1`, executes it remotely, and then removes the remote copy. Adjust `HOST_IP`, `SSH_USER`, and `SSH_KEY` as required.

```bash
./host_hardening_windows.sh
```

2. **Review `vm_windows_env_hardening.sh`**:

   After the host is secured, this script tightens the VM by allowing SSH only from the host IP and disabling VirtualBox clipboard sharing.

---

## Usage

### Running the Custom Kali ISO

1. **Create a New Virtual Machine**:

   - Use virtualization software (e.g., VirtualBox, VMware).
   - Allocate adequate resources (CPU, RAM, Storage).

2. **Attach the Custom ISO**:

   - Mount `kali-custom-auto.iso` as the bootable media.

3. **Boot the VM**:

   - Start the VM; it should automatically install Kali Linux with the predefined security configurations.
    - After the first boot, the system waits for the Windows host defined by `HOST_IP` and then runs `host_hardening_windows.sh` automatically.
    - The first boot also starts **psad** for port-scan detection, verifies packages with **debsums**, records a quick **Lynis** audit report, and schedules daily security scans.
    - When running on a Windows host, the VM automatically applies extra firewall rules and disables clipboard sharing for improved isolation.
    - The network interface MAC address is randomized at each boot for privacy.
    - Optional neural network IDS setup downloads public malware datasets and trains a model if internet access is available.

4. **Initial Login**:

   - Use the non-root user (`KALI_USERNAME_PLACEHOLDER`) with the password set in the preseed file.
   - Alternatively, use SSH with key-based authentication if configured.

### Executing the Host Hardening Script

1. **Ensure Remote Management is Configured**:

   - Verify that PowerShell Remoting or SSH is correctly set up on Windows 11.

2. **Transfer and Execute the Hardening Script**:

   - Follow the steps in [Automating Host Hardening from Kali VM](#4-automating-host-windows-11-hardening-from-kali-vm).

3. **Monitor the Process**:

   - Observe the script's output for successful execution and address any errors.

---

## Security Considerations

- **Protect SSH Keys**: Ensure that SSH private keys are securely stored and have appropriate permissions (`chmod 600`).
- **Secure Script Files**: Maintain the integrity of preseed and hardening scripts by storing them in secure locations.
- **Limit Remote Access**: Restrict SSH access to specific IP addresses and enforce key-based authentication.
- **Audit Logs**: Regularly monitor logs on both Kali VM and Windows host to detect unauthorized access or anomalies.
- **Backup Configurations**: Before applying hardening measures, back up important configurations and data on the Windows host.
- **Regular Updates**: Keep both Kali Linux and Windows 11 systems updated with the latest security patches.

---

## Customization

- **Adjust Firewall Rules**: Modify UFW and Windows Firewall rules based on the specific services and ports required in your environment.
- **Add or Remove Packages**: Customize the list of packages in the preseed file to include or exclude tools as per your security policies.
- **Extend Hardening Scripts**: Enhance the `firstboot.sh` and `windows_hardening.ps1` scripts with additional hardening commands tailored to your needs.
- **Integrate Monitoring Tools**: Incorporate additional monitoring and intrusion detection tools for enhanced security oversight.
- **Tune Scheduled Scans**: Adjust `/etc/cron.d/security-scans` if you need different frequencies for the daily `lynis`, `rkhunter`, and `clamscan` jobs.
- **Modify MAC Randomization**: Edit `/usr/local/bin/mac_randomizer.sh` to target the correct interface or adjust the service schedule.
- **Configure IDS Responses**: Launch the desktop "IDS Control Menu" icon or run `ids_menu.sh` to adjust `NN_IDS_NOTIFY`, `NN_IDS_SANITIZE`, `NN_IDS_DISCOVERY_MODE` (auto|manual|notify|none), `NN_IDS_AUTOBLOCK`, and `NN_IDS_THREAT_FEED`. The menu also lets you list, block, or unblock IP addresses, view recent IDS alerts, training metrics, alert reports, threat feed logs, network I/O logs, port monitor alerts, autoblock actions, process monitor alerts, anti-wipe monitor logs, IDS resource logs, rkhunter scan logs, Lynis scan logs, ClamAV scan logs, and network discovery reports; kick off a new network discovery; sanitize datasets; retrain the model; update the threat feed; snapshot or restore the IDS state; generate adversarial samples; restart the IDS service; run rkhunter, Lynis, or ClamAV scans individually or all at once; run the GA Tech process scan; summarize scan logs. A cron job runs the dashboard at boot.
- **Configure IDS Responses**: Launch the desktop "IDS Control Menu" icon or run `ids_menu.sh` to adjust `NN_IDS_NOTIFY`, `NN_IDS_SANITIZE`, `NN_IDS_DISCOVERY_MODE` (auto|manual|notify|none), `NN_IDS_AUTOBLOCK`, and `NN_IDS_THREAT_FEED`. The menu also lets you list, block, or unblock IP addresses, view recent IDS alerts, training metrics, alert reports, threat feed logs, network I/O logs, port monitor alerts, autoblock actions, process monitor alerts, anti-wipe monitor logs, IDS resource logs, rkhunter scan logs, Lynis scan logs, and network discovery reports; kick off a new network discovery; run rkhunter, Lynis, or ClamAV scans individually or all at once; run the GA Tech process scan; summarize scan logs; sanitize datasets; retrain the model; update the threat feed; snapshot or restore the IDS state; generate adversarial samples; or restart the IDS service. A cron job runs the dashboard at boot.

---

## Troubleshooting

- **ISO Boot Issues**:
  - Verify that the custom ISO is correctly built and marked as bootable.
  - Ensure that virtualization settings (e.g., EFI/BIOS mode) match the ISO configuration.

- **Preseed Errors**:
  - Check the syntax and correctness of the preseed file.
  - Review installation logs for detailed error messages.

- **Remote Connection Failures**:
  - Ensure that SSH or PowerShell Remoting is correctly configured on Windows 11.
  - Verify network connectivity between Kali VM and Windows host.
  - Confirm that firewall rules permit the necessary traffic.

- **Script Execution Problems**:
  - Validate the presence and permissions of the scripts on both Kali and Windows systems.
  - Ensure that all dependencies and prerequisites are met before script execution.
  - Review script logs and output for specific error messages.

---

## Best Practices

- **Regular Security Audits**: Schedule periodic audits using tools like Lynis, RKHunter, and Chkrootkit to maintain system integrity.
- **Centralized Logging and Monitoring**: Implement centralized solutions (e.g., ELK Stack) to aggregate and analyze logs from multiple sources.
- **Principle of Least Privilege**: Assign users only the permissions necessary for their roles to minimize potential security risks.
- **Strong Authentication**: Enforce strong, unique passwords and consider implementing Multi-Factor Authentication (MFA) for critical accounts.
- **Network Segmentation**: Isolate critical systems within separate network segments to reduce the attack surface.
- **Immutable Infrastructure**: Deploy changes through version-controlled scripts and configurations to ensure consistency and traceability.
- **Stay Informed**: Keep abreast of the latest security threats and best practices to adapt your security measures accordingly.

---

## AI-Assisted Improvements

The script `ai_agent_commands.sh` is an optional helper that can send a prompt to a generative AI service, requesting suggestions for further hardening. Set `OPENAI_API_KEY` in your environment and provide a JSON payload describing your code or question:

```bash
echo '{"model":"gpt-4","messages":[{"role":"user","content":"Review my script for security issues."}]}' > prompt.json
./ai_agent_commands.sh prompt.json
```

Responses can guide future enhancements or identify potential weaknesses.

---

## Additional Resources

- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Debian Preseed Documentation](https://www.debian.org/releases/stable/example-preseed.txt)
- [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/overview-of-powershell-remoting)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [AIDE (Advanced Intrusion Detection Environment)](https://aide.github.io/)
- [Fail2Ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Snort Intrusion Detection](https://www.snort.org/)
- [ELK Stack](https://www.elastic.co/what-is/elk-stack)

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Developer Notes

See `DEV_NOTES.md` for planning details and contributor guidelines. Key points:

- Keep scripts modular and well-commented.
- Run the provided shell and Python syntax checks before committing.
- Update the Project Structure section when adding new modules.

---

## Disclaimer

**Use at Your Own Risk**: The configurations and scripts provided in this project are intended for educational and testing purposes. Ensure that you understand each step and customize it according to your specific environment and security requirements before deploying it in a production setting.

---
