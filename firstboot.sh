#!/bin/bash
# /usr/local/bin/firstboot.sh
# First Boot Hardening Script

# Update and Upgrade the System
apt-get update && apt-get upgrade -y

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

# Set up Neural Network IDS (optional)
if [ -x /usr/local/bin/setup_nn_ids.sh ]; then
    /usr/local/bin/setup_nn_ids.sh
fi

# Wait for Windows host to become reachable before running host hardening
HOST_IP="${HOST_IP:-192.168.1.100}"
MAX_WAIT=300
WAIT_INTERVAL=10
TIME_PASSED=0
echo "Waiting for Windows host $HOST_IP..."
until ping -c1 "$HOST_IP" >/dev/null 2>&1; do
    sleep "$WAIT_INTERVAL"
    TIME_PASSED=$((TIME_PASSED + WAIT_INTERVAL))
    if [ "$TIME_PASSED" -ge "$MAX_WAIT" ]; then
        echo "Timeout waiting for $HOST_IP"
        break
    fi
done

if ping -c1 "$HOST_IP" >/dev/null 2>&1 && \
   [ -x /usr/local/bin/host_hardening_windows.sh ]; then
    /usr/local/bin/host_hardening_windows.sh
fi

# Apply additional VM hardening tailored for a Windows host environment
# Apply additional VM hardening tailored for a Windows host environment
if [ -x /usr/local/bin/vm_windows_env_hardening.sh ]; then
    /usr/local/bin/vm_windows_env_hardening.sh
fi

# Schedule recurring security scans
if [ -x /usr/local/bin/security_scan_scheduler.sh ]; then
    /usr/local/bin/security_scan_scheduler.sh
fi

# Initialize process and service monitoring baseline
if [ -x /usr/local/bin/process_service_monitor.py ]; then
    /usr/local/bin/process_service_monitor.py
fi

# Final Cleanup and Disable First Boot Service
systemctl disable firstboot.service
rm /etc/systemd/system/firstboot.service
rm /usr/local/bin/firstboot.sh

echo "First boot hardening completed successfully."
