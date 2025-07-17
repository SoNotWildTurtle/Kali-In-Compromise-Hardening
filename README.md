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
- **Automated Windows 11 Host Hardening**: Utilizes PowerShell scripts to remotely harden a Windows 11 host from the Kali VM.
- **Automated Windows Remote Setup**: The Windows hardening script installs and enables OpenSSH and PowerShell Remoting, enables transcript logging, and schedules daily updates.
- **Windows Host-Aware VM Hardening**: Additional firewall and virtualization tweaks protect the Kali VM when running on a Windows host.
- **AI Agent Integration**: Optional script demonstrates how to request code improvement suggestions from a generative AI service.
- **Comprehensive Documentation**: Detailed instructions to guide users through setup, customization, and maintenance.
- **Secure Remote Management**: Configures secure communication channels between Kali VM and Windows host using SSH or PowerShell Remoting.
- **Port Scan Detection with psad**: Monitors iptables logs for potential network attacks.
- **Baseline Auditing**: First boot verifies package integrity with `debsums` and performs a quick Lynis scan.
- **Scheduled Security Scans**: Daily `lynis` and `rkhunter` checks are configured via cron.
- **MAC Address Randomization**: The primary network interface receives a new MAC on each boot.
- **Neural Network IDS**: Scripts fetch GA Tech malware datasets, train a neural network model, capture live traffic for additional learning, and periodically retrain the model.
- **Process and Service Monitoring**: A systemd timer runs a Python script that records a baseline of running processes and services and alerts when new or suspicious entries appear.

---

## Project Structure

Scripts are organized as modules that work together to produce the hardened image:

- `kali-preseed.cfg` – Automates the base installation and seeds security packages.
- `firstboot.sh` – Runs once after installation to apply further hardening and invoke other modules.
- `host_hardening_windows.sh` and `windows_hardening.ps1` – Harden a Windows host from the VM.
- `vm_windows_env_hardening.sh` – Applies additional VM protections when a Windows host is detected.
- `security_scan_scheduler.sh` – Sets up recurring Lynis and rkhunter scans.
- `process_service_monitor.py` – Monitors running processes and services via a systemd timer.
- `setup_nn_ids.sh`, `nn_ids_setup.py`, `nn_ids_service.py`, `nn_ids_capture.py`, and `nn_ids_retrain.py` – Download datasets, train the neural network IDS, capture live traffic, and periodically retrain the model.
- `mac_randomizer.sh` and `mac_randomizer.service` – Randomize the MAC address at boot.
- `build_custom_iso.sh` – Helper to package the above into a custom ISO.

These modules are referenced in the preseed late commands and copied onto the ISO so the system is secured immediately after installation.

---

## Prerequisites

### Hardware

- **Host Machine**: Windows 11 PC with virtualization support (e.g., Intel VT-x or AMD-V).
- **Resources**: Adequate CPU, RAM, and storage to support Kali Linux VM and host operations.

### Software

- **Kali Linux ISO**: Download the latest version from [Kali Downloads](https://www.kali.org/get-kali/).
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
   d-i passwd/root-password password YOUR_SECURE_ROOT_PASSWORD
   d-i passwd/root-password-again password YOUR_SECURE_ROOT_PASSWORD

   ## Non-root User
   d-i passwd/user-fullname string KaliUser
   d-i passwd/username string kaliuser
   d-i passwd/user-password password USER_SECURE_PASSWORD
   d-i passwd/user-password-again password USER_SECURE_PASSWORD
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
       chmod 700 /home/kaliuser; \
       echo "Authorized access only. Activity may be monitored." > /target/etc/issue; \
       cp /target/etc/issue /target/etc/issue.net; \
       in-target systemctl mask ctrl-alt-del.target; \
       echo "blacklist usb-storage" > /target/etc/modprobe.d/blacklist-usb.conf; \
       \
       # Enforce Password Policies \
       chage --maxdays 90 kaliuser; \
       chage --maxdays 90 root; \
       \
       # Remove Unnecessary Services and Packages \
       apt-get remove --purge -y telnet ftp nfs-common rpcbind; \
       apt-get autoremove -y; \
       apt-get clean; \
       \
       # Bash Configuration Enhancements \
       echo "alias ll='ls -la'" >> /home/kaliuser/.bashrc; \
       chown kaliuser:kaliuser /home/kaliuser/.bashrc; \
       echo "export HISTCONTROL=ignoredups:erasedups" >> /home/kaliuser/.bashrc; \
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

   - `YOUR_SECURE_ROOT_PASSWORD`: Replace with a strong, unique password for the root account.
   - `USER_SECURE_PASSWORD`: Replace with a strong, unique password for the non-root user (`kaliuser`).
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

The custom ISO incorporates the preseed file to automate installation and hardening.

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

   Test the ISO in a virtual machine environment (e.g., VirtualBox, VMware) before deploying it in production.
Alternatively, run the provided `build_custom_iso.sh` script to automate these steps:

```bash
./build_custom_iso.sh kali-linux-latest-amd64.iso kali-custom-auto.iso
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
   scp windows_hardening.ps1 kaliuser@kali-vm:/home/kaliuser/
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

   - Use the non-root user (`kaliuser`) with the password set in the preseed file.
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
- **Tune Scheduled Scans**: Adjust `/etc/cron.d/security-scans` if you need different frequencies for the daily `lynis` and `rkhunter` jobs.
- **Modify MAC Randomization**: Edit `/usr/local/bin/mac_randomizer.sh` to target the correct interface or adjust the service schedule.

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
