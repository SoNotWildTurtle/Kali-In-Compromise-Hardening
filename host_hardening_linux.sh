#!/bin/bash
# host_hardening_linux.sh - automate hardening of a Linux host via SSH
set -euo pipefail

HOST_IP="${HOST_IP:-192.168.1.200}"
SSH_USER="${SSH_USER:-root}"
SSH_KEY="${SSH_KEY:-/home/kaliuser/.ssh/id_rsa_kali_linux}"

ssh -i "$SSH_KEY" "$SSH_USER@$HOST_IP" bash -s <<'EOS'
set -e
apt-get update && apt-get upgrade -y
apt-get install -y ufw fail2ban auditd unattended-upgrades rkhunter lynis

ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable

systemctl enable --now fail2ban
systemctl enable --now auditd

# Harden SSH configuration
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Enable unattended upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# Run baseline scans
rkhunter --update && rkhunter --propupd
rkhunter --check --skip-keypress
lynis audit system --quick
EOS

echo "Linux host hardening process completed."
