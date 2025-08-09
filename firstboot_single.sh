#!/bin/bash
# /usr/local/bin/firstboot.sh
# First Boot Hardening Script

# Ensure internet connectivity before updates
if [ -x /usr/local/bin/internet_access_monitor.sh ]; then
    /usr/local/bin/internet_access_monitor.sh
fi

# Update and Upgrade the System
apt-get update && apt-get upgrade -y

# Install tools for anti-wiper monitoring and protect critical files
apt-get install -y inotify-tools
mkdir -p /root/critical_backup
cp -a /etc/passwd /etc/shadow /etc/group /etc/gshadow /root/critical_backup/
chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow /root/critical_backup/*

# Enable network I/O monitoring before other services start
if [ -x /usr/local/bin/network_io_monitor.sh ]; then
    /usr/local/bin/network_io_monitor.sh
fi
if [ -x /usr/local/bin/secure_dev_env.sh ]; then
    /usr/local/bin/secure_dev_env.sh
fi

# Configure Docker Security
usermod -aG docker kaliuser
systemctl enable docker
systemctl start docker

# Implement Docker Daemon Security
mkdir -p /etc/docker
cat <<EOF > /etc/docker/daemon.json
{
    "icc": false,
    "userns-remap": "default",
    "no-new-privileges": true,
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF
systemctl restart docker

# Enable Docker Content Trust
echo "export DOCKER_CONTENT_TRUST=1" >> /etc/profile.d/docker.sh

# Configure AIDE for File Integrity Monitoring
aide --init
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule Regular AIDE Checks
echo "0 3 * * * root /usr/bin/aide --check" >> /etc/crontab

# Enhance Logging with Logrotate for Security Logs
cat <<EOF > /etc/logrotate.d/security
/var/log/audit/audit.log {
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        /sbin/service auditd reload > /dev/null
    endscript
}
EOF

# Harden Network Configuration with Additional Sysctl Settings
cat <<EOF >> /etc/sysctl.conf
# Additional Network Hardening
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.ip_local_port_range=1024 65535
net.core.somaxconn=1024
EOF
sysctl -p

# Disable IPv6 if Not Needed
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Secure Shared Memory
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab

# Install and Configure Intrusion Detection System (Snort)
apt-get install -y snort
# Configure Snort rules as per your environment

# Enable psad for port scan detection
apt-get install -y psad debsums lynis
ufw logging on
psad --sig-update
systemctl enable psad
systemctl start psad

# Verify package integrity
debsums -s > /var/log/debsums.log || true

# Run a baseline security audit
lynis audit system --quick > /var/log/lynis.log || true

# Set up Neural Network IDS asynchronously (optional)
if systemctl list-unit-files | grep -q '^setup_nn_ids.service'; then
    systemctl start setup_nn_ids.service &
fi
if systemctl list-unit-files | grep -q '^nn_ids_capture.timer'; then
    systemctl start nn_ids_capture.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_retrain.timer'; then
    systemctl start nn_ids_retrain.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_healthcheck.timer'; then
    systemctl start nn_ids_healthcheck.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_snapshot.timer'; then
    systemctl start nn_ids_snapshot.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_restore.timer'; then
    systemctl start nn_ids_restore.timer
fi
if systemctl list-unit-files | grep -q '^internet_access_monitor.timer'; then
    systemctl start internet_access_monitor.timer
fi




if [ -x /usr/local/bin/host_hardening_linux.sh ]; then
    /usr/local/bin/host_hardening_linux.sh
fi


if [ -x /usr/local/bin/vm_linux_env_hardening.sh ]; then
    /usr/local/bin/vm_linux_env_hardening.sh
fi

# Schedule recurring security scans
if [ -x /usr/local/bin/security_scan_scheduler.sh ]; then
    /usr/local/bin/security_scan_scheduler.sh
fi

# Initialize process and service monitoring baseline
if [ -x /usr/local/bin/process_service_monitor.py ]; then
    /usr/local/bin/process_service_monitor.py
fi

# Start port and socket monitoring
if [ -x /usr/local/bin/port_socket_monitor.py ]; then
    /usr/local/bin/port_socket_monitor.py
fi
if systemctl list-unit-files | grep -q '^port_socket_monitor.timer'; then
    systemctl start port_socket_monitor.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_autoblock.timer'; then
    systemctl start nn_ids_autoblock.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_report.timer'; then
    systemctl start nn_ids_report.timer
fi
if systemctl list-unit-files | grep -q '^threat_feed_blocklist.timer'; then
    systemctl start threat_feed_blocklist.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_resource_monitor.timer'; then
    systemctl start nn_ids_resource_monitor.timer
fi
if systemctl list-unit-files | grep -q '^nn_ids_sanitize.timer'; then
    systemctl start nn_ids_sanitize.timer
fi
if systemctl list-unit-files | grep -q '^anti_wipe_monitor.service'; then
    systemctl start anti_wipe_monitor.service
fi
if [ -x /usr/local/bin/vm_pro_hardening.sh ]; then
    /usr/local/bin/vm_pro_hardening.sh
fi

# Perform initial network discovery and diagnostics
if [ -x /usr/local/bin/network_discovery.sh ]; then
    /usr/local/bin/network_discovery.sh
fi

# Launch IDS configuration menu for user interaction
if [ -x /usr/local/bin/ids_menu.sh ]; then
    if command -v x-terminal-emulator >/dev/null 2>&1; then
        x-terminal-emulator -e /usr/local/bin/ids_menu.sh &
    else
        /usr/local/bin/ids_menu.sh
    fi
fi

# Final Cleanup and Disable First Boot Service
systemctl disable firstboot.service
rm /etc/systemd/system/firstboot.service
rm /usr/local/bin/firstboot.sh

echo "First boot hardening completed successfully."
