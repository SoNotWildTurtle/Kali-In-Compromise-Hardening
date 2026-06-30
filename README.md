# Alexander Raymond Graham:
# Minc- Anonymous
# Whitehatting within a compromised windows 11 environment
# Automated Secure Kali Linux VM with Windows 11 Host Hardening

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
- **Automated Windows 11 Host Hardening**: Utilizes PowerShell scripts to remotely harden a Windows 11 host from the Kali VM.
- **Automated Windows Remote Setup**: The Windows hardening script installs and enables OpenSSH and PowerShell Remoting, enables transcript logging, and schedules daily updates.
- **Windows Host-Aware VM Hardening**: Additional firewall and virtualization tweaks protect the Kali VM when running on a Windows host.
- **AI Agent Integration**: Optional script demonstrates how to request code improvement suggestions from a generative AI service.
- **Comprehensive Documentation**: Detailed instructions to guide users through setup, customization, and maintenance.
- **Secure Remote Management**: Configures secure communication channels between Kali VM and Windows host using SSH or PowerShell Remoting.
- **Port Scan Detection with psad**: Monitors iptables logs for potential network attacks.
- **Baseline Auditing**: First boot verifies package integrity with `debsums` and performs a quick Lynis scan.
- **Scheduled Security Scans**: Daily `lynis` and `rkhunter` checks are configured via cron.
- **Wiper and Malware Protection**: ClamAV runs daily scans, critical system files are backed up and locked with immutable attributes, and an inotify-based monitor watches for deletion attempts to thwart destructive wipers.
- **MAC Address Randomization**: The primary network interface receives a new MAC on each boot.
- **Port-Separated Network I/O Logging**: All inbound traffic is forced through port 5775 and outbound traffic through port 7557, with each direction logged from the first boot for review.
- **Internet Connectivity Guard**: A periodic check keeps outbound access open, enforces the dedicated 5775/7557 port split, and restores networking if connectivity is lost, activating SD-WAN, Cisco, or VMware interfaces to maintain at least one active link.
- **Initial Network Discovery**: After hardening completes, a one-time sweep leverages `nmap`, `netdiscover`, `arp-scan`, `nbtscan`, `dnsrecon`, and optional `whatweb`/`enum4linux` probes to profile local hosts, services, DNS/NetBIOS data, and web fingerprints, saving logs and an HTML visualization to `~/Desktop/initial network discovery`, including a verification that only ports 5775 and 7557 are reachable locally.
- **Network I/O Logging**: Inbound and outbound traffic is logged from the first boot for review.
- **Internet Connectivity Guard**: A periodic check keeps outbound access open and restores networking if connectivity is lost, activating SD-WAN, Cisco, or VMware interfaces to maintain at least one active link.
- **Initial Network Discovery**: After hardening completes, a one-time sweep leverages `nmap`, `netdiscover`, `arp-scan`, `nbtscan`, `dnsrecon`, and optional `whatweb`/`enum4linux` probes to profile local hosts, services, DNS/NetBIOS data, and web fingerprints, saving logs and an HTML visualization to `~/Desktop/initial network discovery`.
- **IDS Control Menu**: A terminal menu toggles malicious packet notifications and selects how aggressively to launch follow-up network discovery when alerts occur.
- **Secure Coding Environment**: Optional script installs Visual Studio Code (code-oss) and configures git with secure defaults. Static analysis tools are enabled via pre-commit hooks and a GPG key is generated so commits are signed automatically.
- **Professional VM Hardening**: Extra kernel hardening, secure tmp mount, AppArmor enforcement, and needrestart ensure the VM meets professional standards.
- **Neural Network IDS**: Scripts fetch GA Tech malware datasets, train a neural network model, capture live traffic for additional learning, and periodically retrain the model. Training runs in parallel with packet capture and live analysis using systemd services.
- **OS Baseline Modeling**: A small neural network records core OS characteristics to detect future configuration drift.
- **MAC Address Randomization**: The primary network interface receives a new MAC on each boot.
- **Neural Network IDS**: Scripts fetch GA Tech malware datasets, train a neural network model, capture live traffic for additional learning, and periodically retrain the model. Training runs in parallel with packet capture and live analysis using systemd services.
- **Training Metrics Logging**: Accuracy and F1 score are recorded after each training or retraining run.
- **IDS Hardening Defenses**: Dataset integrity checks, outlier removal, noise augmentation, and detection of repeated evasion attempts guard against poisoning and desensitization attacks.
- **Process and Service Monitoring**: A systemd timer runs a Python script that records a baseline of running processes and services and alerts when new or suspicious entries appear.
- **IDS Health Check and Log Rotation**: Additional timer ensures the IDS service is running and rotates IDS logs to prevent disk bloat.
- **IDS Resource Usage Monitoring**: Another timer verifies the IDS process stays within CPU and memory limits, restarting it if needed.
- **Training Log Rotation**: Model training metrics are logged and rotated to keep logs manageable.
- **Packet Sanitization**: Captured datasets are sanitized before training to remove malformed or out-of-range values. This can be toggled by editing `/etc/nn_ids.conf` and setting `NN_IDS_SANITIZE=0`.
- **Automated Dataset Sanitization**: A timer-driven script periodically cleans the IDS datasets to prevent poisoning.
- **Packet Sanitization**: Captured datasets are sanitized before training to remove malformed or out-of-range values.
- **Smart Port Monitoring**: A timer-driven script records listening ports and logs unexpected changes.
- **Automatic IP Blocking**: Repeated IDS alerts trigger a script that blocks offending IP addresses via iptables.
- **Probability-Based Alerts**: IDS alerts include a confidence score so you can tune responses to low or high certainty events.
- **Auto-Unblocking**: Blocked IPs are automatically removed after 24 hours to avoid permanent bans.
- **IDS Alert Reporting**: A timer summarizes new IDS alerts each hour and logs counts of offending IPs.
- **Threat Feed IP Blocking**: Daily job fetches community blocklists and automatically drops traffic from known malicious IPs.
- **Self-Healing Snapshots**: Daily snapshots of the IDS model and datasets allow automatic restoration or retraining if files are wiped.
- **IDS Hardening Defenses**: Dataset integrity checks, outlier removal, noise augmentation, and detection of repeated evasion attempts guard against poisoning and desensitization attacks.
- **Process and Service Monitoring**: A systemd timer runs a Python script that records a baseline of running processes and services and alerts when new or suspicious entries appear.
- **IDS Health Check and Log Rotation**: Additional timer ensures the IDS service is running and rotates IDS logs to prevent disk bloat.
- **Packet Sanitization**: Captured datasets are sanitized before training to remove malformed or out-of-range values.
- **Smart Port Monitoring**: A timer-driven script records listening ports and logs unexpected changes.
- **Automatic IP Blocking**: Repeated IDS alerts trigger a script that blocks offending IP addresses via iptables.
- **IDS Alert Reporting**: A timer summarizes new IDS alerts each hour and logs counts of offending IPs.
- **Threat Feed IP Blocking**: Daily job fetches community blocklists and automatically drops traffic from known malicious IPs.
- **Release Posture Summary**: Passive aggregate CLI combines firstboot and restore readiness summaries into one fail-closed reviewer handoff artifact without reading raw telemetry or mutating host/VM state.

---

## Project Structure

Scripts are organized as modules that work together to produce the hardened image:

- `kali-preseed.cfg` – Automates the base installation and seeds security packages.
- `kali-preseed-single.cfg` – Variant preseed for single-OS installs without Windows host hardening.
- `firstboot.sh` – Runs once after installation to apply further hardening and invoke other modules.
