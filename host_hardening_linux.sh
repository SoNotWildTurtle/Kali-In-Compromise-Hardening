#!/bin/bash
# host_hardening_linux.sh - automate hardening of a Linux host via SSH
set -euo pipefail

HOST_IP="${HOST_IP:-192.168.1.200}"
SSH_USER="${SSH_USER:-root}"
SSH_KEY="${SSH_KEY:-/home/kaliuser/.ssh/id_rsa_kali_linux}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANTI_WIPE_SCRIPT="${ANTI_WIPE_SCRIPT:-$SCRIPT_DIR/anti_wipe_monitor.sh}"
ANTI_WIPE_SERVICE="${ANTI_WIPE_SERVICE:-$SCRIPT_DIR/anti_wipe_monitor.service}"
CHANNEL_POLICY_VALIDATOR="${CHANNEL_POLICY_VALIDATOR:-$SCRIPT_DIR/host_vm_channel_policy.py}"
CHANNEL_POLICY_FILE="${CHANNEL_POLICY_FILE:-$SCRIPT_DIR/host_vm_channel_policy.example.json}"
CHANNEL_POLICY_CHECK_LOCAL_FILES="${CHANNEL_POLICY_CHECK_LOCAL_FILES:-1}"

run_channel_policy_preflight() {
    if [ "${KALI_HARDENING_SKIP_CHANNEL_POLICY:-0}" = "1" ]; then
        cat >&2 <<'WARN'
WARNING: KALI_HARDENING_SKIP_CHANNEL_POLICY=1 is set.
The host/VM management-channel policy preflight is being bypassed for a documented break-glass session.
Capture transcript logs, keep the maintenance window short, and rerun policy validation before normal automation resumes.
WARN
        return 0
    fi

    if [ ! -r "$CHANNEL_POLICY_VALIDATOR" ]; then
        echo "Channel policy validator is missing or unreadable: $CHANNEL_POLICY_VALIDATOR" >&2
        exit 1
    fi

    if [ ! -f "$CHANNEL_POLICY_FILE" ]; then
        echo "Channel policy file not found: $CHANNEL_POLICY_FILE" >&2
        exit 1
    fi

    local validator_args=(--policy "$CHANNEL_POLICY_FILE")
    if [ "$CHANNEL_POLICY_CHECK_LOCAL_FILES" = "1" ]; then
        validator_args+=(--check-local-files)
    fi

    echo "Validating host/VM hardening channel policy before Linux host automation..."
    python3 "$CHANNEL_POLICY_VALIDATOR" "${validator_args[@]}"
}

run_channel_policy_preflight

scp -i "$SSH_KEY" "$ANTI_WIPE_SCRIPT" "$SSH_USER@$HOST_IP:/tmp/anti_wipe_monitor.sh"
scp -i "$SSH_KEY" "$ANTI_WIPE_SERVICE" "$SSH_USER@$HOST_IP:/tmp/anti_wipe_monitor.service"

ssh -i "$SSH_KEY" "$SSH_USER@$HOST_IP" bash -s <<'EOS'
set -e
apt-get update && apt-get upgrade -y
apt-get install -y ufw fail2ban auditd unattended-upgrades rkhunter lynis clamav clamav-daemon apparmor apparmor-utils aide

ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable

systemctl enable --now fail2ban
systemctl enable --now auditd
systemctl enable --now clamav-freshclam
systemctl enable --now clamav-daemon
systemctl enable --now apparmor
aa-enforce /etc/apparmor.d/*

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
aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule daily malware scan
cat <<'CRON' >/etc/cron.d/clamav-scan
0 3 * * * root /usr/bin/clamscan -ri / --exclude-dir="^/sys|^/proc|^/dev|^/run|^/tmp" >> /var/log/clamav_cron.log 2>&1
CRON
chmod 600 /etc/cron.d/clamav-scan

# Install anti-wiper monitor and protect critical files
apt-get install -y inotify-tools
mv /tmp/anti_wipe_monitor.sh /usr/local/bin/anti_wipe_monitor.sh
chmod +x /usr/local/bin/anti_wipe_monitor.sh
mv /tmp/anti_wipe_monitor.service /etc/systemd/system/anti_wipe_monitor.service
mkdir -p /root/critical_backup
cp -a /etc/passwd /etc/shadow /etc/group /etc/gshadow /root/critical_backup/
chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow /root/critical_backup/*
systemctl enable anti_wipe_monitor.service
systemctl start anti_wipe_monitor.service
# Apply additional kernel hardening
cat <<'SYSCTL' >/etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv6.conf.all.accept_redirects=0
kernel.kptr_restrict=2
kernel.randomize_va_space=2
SYSCTL
sysctl -p /etc/sysctl.d/99-hardening.conf
EOS

echo "Linux host hardening process completed."
