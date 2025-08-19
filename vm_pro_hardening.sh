#!/bin/bash
# vm_pro_hardening.sh - Professional-level hardening for Kali VM
set -euo pipefail

# Kernel hardening parameters
cat <<'SYSCTL' > /etc/sysctl.d/pro_hardening.conf
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.sysrq=0
kernel.unprivileged_userns_clone=0
kernel.yama.ptrace_scope=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
SYSCTL

sysctl --system

# Harden temporary directories
mount -o remount,noexec,nosuid,nodev /tmp || true
grep -q '^tmpfs /tmp' /etc/fstab || echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab

# Install needrestart for auto restarting services after updates
apt-get install -y needrestart

# Enforce all AppArmor profiles
if command -v aa-enforce >/dev/null 2>&1; then
    aa-enforce /etc/apparmor.d/* || true
fi
